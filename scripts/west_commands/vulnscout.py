# Copyright (c) 2026
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import glob
import os
import pathlib
import shutil
import subprocess
import textwrap
import time

from west.commands import WestCommand
from west.util import quote_sh_list


# Keep defaults aligned with the VulnScout wrapper script.
VULNSCOUT_IMAGE_REPO = os.environ.get('VULNSCOUT_IMAGE_REPO', 'docker.io/sflinux/vulnscout')
VULNSCOUT_VERSION = (
    os.environ.get('VULNSCOUT_VERSION')
    or os.environ.get('VULNSCOT_VERSION')
    or 'v0.23'
)
DEFAULT_VULNSCOUT_IMAGE = f'{VULNSCOUT_IMAGE_REPO}:{VULNSCOUT_VERSION}'


VULNSCOUT_DESCRIPTION = """\
Generate SPDX SBOM files using west spdx, then import them into VulnScout.

By default this command runs `west spdx --spdx-version 3.0`, then imports all
`*.jsonld` files from the SPDX output directory into VulnScout using
`--add-spdx` via `docker exec` or `podman exec`. In direct mode it mounts
`<build-dir>/../.vulnscout/cache` to `/cache/vulnscout` for persistent database
storage."""


class ZephyrVulnScout(WestCommand):
    def __init__(self):
        super().__init__('vulnscout', '', description=VULNSCOUT_DESCRIPTION)

    def do_add_parser(self, parser_adder):
        parser = parser_adder.add_parser(
            self.name,
            description=self.description,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=textwrap.dedent(
                """\
            Examples:

                # Build first (with CONFIG_BUILD_OUTPUT_META=y), then:
                west vulnscout -d build

                                # Direct container exec mode:
                                west vulnscout -d build --serve

                                # Wrapper mode with custom VulnScout image and dev mode:
                                west vulnscout -d build --vulnscout-cmd vulnscout \
                                    --vulnscout-image sfl:custom --serve --dev

                # Skip SPDX generation and import an existing SPDX output directory:
                west vulnscout -d build --no-generate --spdx-dir build/spdx

                # Stop the VulnScout container and exit:
                west vulnscout stop

                # Request SPDX 3.1 explicitly (requires spdx-python-model v3_1):
                west vulnscout -d build --spdx-version 3.1
            """
            ),
        )

        parser.add_argument(
            'action',
            nargs='?',
            choices=['stop'],
            help='stop the VulnScout container and exit (alias for --stop)',
        )
        parser.add_argument('-d', '--build-dir', help='Zephyr build directory')
        parser.add_argument(
            '--spdx-dir',
            help='SPDX output directory (default: <build-dir>/spdx)',
        )
        parser.add_argument(
            '--spdx-version',
            choices=['3.0', '3.1'],
            default='3.0',
            help='SPDX specification version passed to west spdx (default: 3.0)',
        )
        parser.add_argument(
            '--namespace-prefix',
            help='namespace prefix passed to west spdx',
        )
        parser.add_argument(
            '--include-sdk',
            action='store_true',
            help='also generate SPDX document for SDK',
        )
        parser.add_argument(
            '--analyze-includes',
            action='store_true',
            help='also analyze included header files',
        )
        parser.add_argument(
            '--no-generate',
            action='store_true',
            help='skip west spdx generation and reuse files from --spdx-dir',
        )
        parser.add_argument(
            '--stop',
            action='store_true',
            help='stop VulnScout container and exit',
        )
        parser.add_argument(
            '--stop-after-run',
            action='store_true',
            help='stop VulnScout container after a successful run',
        )
        parser.add_argument(
            '--spdx-file',
            action='append',
            default=[],
            help='specific SPDX file to import (can be used multiple times)',
        )
        parser.add_argument(
            '--project',
            default='default',
            help='VulnScout project name (default: default)',
        )
        parser.add_argument(
            '--variant',
            default='default',
            help='VulnScout variant name (default: default)',
        )
        parser.add_argument(
            '--vulnscout-cmd',
            help='optional VulnScout wrapper command or absolute path',
        )
        parser.add_argument(
            '--vulnscout-image',
            help=(
                'container image repository or repository:tag override '
                '(when tag is omitted, VULNSCOUT_VERSION is used) '
                f'(default: {DEFAULT_VULNSCOUT_IMAGE})'
            ),
        )
        parser.add_argument(
            '--container-engine',
            choices=['auto', 'docker', 'podman'],
            default='auto',
            help='container engine for direct exec mode (default: auto)',
        )
        parser.add_argument(
            '--container-name',
            default='vulnscout',
            help='VulnScout container name for direct exec mode (default: vulnscout)',
        )
        parser.add_argument(
            '--vulnscout-data-dir',
            help=(
                'host directory mounted to /cache/vulnscout in direct mode '
                '(default: <build-dir>/../.vulnscout/cache)'
            ),
        )
        parser.add_argument(
            '--serve',
            action='store_true',
            help='pass --serve to VulnScout',
        )
        parser.add_argument(
            '--dev',
            action='store_true',
            help='pass --dev to VulnScout (wrapper mode only)',
        )
        parser.add_argument(
            '--refresh-vulnerability-data',
            action='store_true',
            help='pass --refresh-vulnerability-data to VulnScout',
        )
        parser.add_argument(
            '--match-condition',
            help='pass --match-condition to VulnScout',
        )

        return parser

    def do_run(self, args, unknown_args):
        if unknown_args:
            self.die(f'Unexpected arguments: {unknown_args}')

        if args.action == 'stop' or args.stop:
            self._stop_vulnscout_container(args)
            return

        if not args.build_dir:
            self.die('Build directory not specified; call `west vulnscout --build-dir=BUILD_DIR`')

        build_dir = os.path.abspath(args.build_dir)
        spdx_dir = os.path.abspath(args.spdx_dir or os.path.join(build_dir, 'spdx'))

        if not os.path.isdir(build_dir):
            self.die(f'Build directory does not exist: {build_dir}')

        if args.serve and args.stop_after_run:
            self.die(
                '--stop-after-run cannot be used with --serve. '
                '--serve keeps VulnScout attached to the terminal. '
                'Use --serve without --stop-after-run, or run without --serve for one-shot scans.'
            )

        if not args.no_generate:
            self._run_west_spdx(args, build_dir, spdx_dir)

        spdx_files = self._resolve_spdx_files(args.spdx_file, spdx_dir)
        if not spdx_files:
            self.die(
                f'No SPDX files found to import in {spdx_dir}. '
                f'Expected *.jsonld, *.spdx.json, or *.spdx files.'
            )

        data_dir = self._resolve_vulnscout_data_dir(args, build_dir)

        try:
            self._run_vulnscout(args, spdx_files, data_dir)
        except KeyboardInterrupt:
            if args.serve and not args.vulnscout_cmd:
                self.wrn('Interrupted by user; stopping VulnScout container')
                self._stop_vulnscout_container(args, best_effort=True)
                return
            raise

        if args.stop_after_run:
            self._stop_vulnscout_container(args)

    def _resolve_container_engine(self, preferred):
        if preferred in ('docker', 'podman'):
            if shutil.which(preferred):
                return preferred
            self.die(f'Requested container engine is not available: {preferred}')

        # auto mode
        for candidate in ('podman', 'docker'):
            if shutil.which(candidate):
                return candidate

        self.die('Could not find podman or docker in PATH')

    def _assert_container_running(self, engine, container_name):
        ps_cmd = [engine, 'ps', '--format', '{{.Names}}']
        try:
            output = subprocess.run(ps_cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            self.die(f'Failed to query running containers with {engine}: exit code {e.returncode}')

        running = output.stdout.splitlines()
        if container_name not in running:
            self.die(
                f'Container "{container_name}" is not running. '
                f'Start VulnScout first or pass --vulnscout-cmd to use the wrapper script.'
            )

    def _is_container_running(self, engine, container_name):
        ps_cmd = [engine, 'ps', '--format', '{{.Names}}']
        try:
            output = subprocess.run(ps_cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            self.die(f'Failed to query running containers with {engine}: exit code {e.returncode}')
        return container_name in output.stdout.splitlines()

    def _is_container_present(self, engine, container_name):
        ps_cmd = [engine, 'ps', '-a', '--format', '{{.Names}}']
        try:
            output = subprocess.run(ps_cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            self.die(f'Failed to query containers with {engine}: exit code {e.returncode}')
        return container_name in output.stdout.splitlines()

    def _wait_for_container_ready(self, engine, container_name, retries=10):
        for _ in range(retries):
            probe = [engine, 'exec', container_name, 'true']
            if subprocess.run(probe, capture_output=True).returncode == 0:
                return
            time.sleep(1)
        self.die(
            f'Container "{container_name}" did not become ready. '
            f'Check logs with: {engine} logs {container_name}'
        )

    def _resolve_vulnscout_image(self, args):
        repo, version = self._resolve_vulnscout_repo_and_version(args)
        return f'{repo}:{version}'

    def _resolve_vulnscout_data_dir(self, args, build_dir):
        if args.vulnscout_data_dir:
            return os.path.abspath(args.vulnscout_data_dir)
        return os.path.abspath(os.path.join(build_dir, '..', '.vulnscout', 'cache'))

    def _resolve_vulnscout_repo_and_version(self, args):
        repo = VULNSCOUT_IMAGE_REPO
        version = VULNSCOUT_VERSION

        if not args.vulnscout_image:
            return repo, version

        override = args.vulnscout_image.strip()
        if not override:
            return repo, version

        # Tag separator is ':' after the last '/'.
        last_slash = override.rfind('/')
        last_colon = override.rfind(':')
        if last_colon > last_slash:
            image_repo, image_tag = override.rsplit(':', 1)
            if image_repo and image_tag:
                return image_repo, image_tag

        return override, version

    def _set_vulnscout_image_env(self, env, args):
        repo, version = self._resolve_vulnscout_repo_and_version(args)
        env['VULNSCOUT_IMAGE_REPO'] = repo
        env['VULNSCOUT_VERSION'] = version
        # Keep compatibility with wrapper scripts still reading this typo.
        env['VULNSCOT_VERSION'] = version
        env['VULNSCOUT_IMAGE'] = f'{repo}:{version}'

    def _get_container_data_mount(self, engine, container_name):
        inspect_cmd = [
            engine,
            'inspect',
            '--format',
            '{{range .Mounts}}{{if eq .Destination "/cache/vulnscout"}}{{.Source}}{{end}}{{end}}',
            container_name,
        ]
        try:
            output = subprocess.run(inspect_cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            self.die(f'Failed to inspect container "{container_name}": exit code {e.returncode}')
        return output.stdout.strip()

    def _ensure_container_running(self, engine, container_name, args, data_dir):
        if self._is_container_running(engine, container_name):
            current_mount = self._get_container_data_mount(engine, container_name)
            if not current_mount:
                self.wrn(
                    f'Container "{container_name}" has no /cache/vulnscout host mount; '
                    'database is not persistent. '
                    f'Expected mount source: {data_dir}'
                )
            elif os.path.abspath(current_mount) != data_dir:
                self.wrn(
                    f'Container "{container_name}" uses /cache/vulnscout from {current_mount} '
                    f'instead of requested {data_dir}'
                )
            return

        if self._is_container_present(engine, container_name):
            current_mount = self._get_container_data_mount(engine, container_name)
            if not current_mount:
                self.wrn(
                    f'Existing container "{container_name}" has no /cache/vulnscout host mount; '
                    'database is not persistent. '
                    f'Expected mount source: {data_dir}'
                )
            elif os.path.abspath(current_mount) != data_dir:
                self.wrn(
                    f'Existing container "{container_name}" uses /cache/vulnscout from {current_mount} '
                    f'instead of requested {data_dir}'
                )
            start_cmd = [engine, 'start', container_name]
            self.inf(f'Starting existing VulnScout container: {quote_sh_list(start_cmd)}')
            try:
                subprocess.run(start_cmd, check=True)
            except subprocess.CalledProcessError as e:
                self.die(f'Failed to start container "{container_name}": exit code {e.returncode}')
            self._wait_for_container_ready(engine, container_name)
            return

        os.makedirs(data_dir, exist_ok=True)
        image = self._resolve_vulnscout_image(args)
        run_cmd = [
            engine,
            'run',
            '-d',
            '--name',
            container_name,
            '-p',
            '7275:7275',
            '-v',
            f'{data_dir}:/cache/vulnscout',
            image,
            'daemon',
        ]
        self.inf(f'Starting VulnScout container: {quote_sh_list(run_cmd)}')
        try:
            subprocess.run(run_cmd, check=True)
        except subprocess.CalledProcessError as e:
            self.die(f'Failed to run VulnScout container from image {image}: exit code {e.returncode}')
        self._wait_for_container_ready(engine, container_name)

    def _stage_spdx_files(self, engine, container_name, spdx_files):
        staged = []
        for idx, spdx_file in enumerate(spdx_files, start=1):
            src_path = pathlib.Path(spdx_file)
            basename = src_path.name
            if src_path.suffix.lower() == '.jsonld':
                basename = f'{src_path.stem}.spdx.json'
            staged_path = f'/tmp/vulnscout_stage_{idx}_{basename}'
            cp_cmd = [engine, 'cp', spdx_file, f'{container_name}:{staged_path}']
            self.dbg(f'Staging SPDX file into container: {quote_sh_list(cp_cmd)}')
            try:
                subprocess.run(cp_cmd, check=True)
            except subprocess.CalledProcessError as e:
                self.die(f'Failed to stage SPDX file {spdx_file}: exit code {e.returncode}')
            staged.append(staged_path)
        return staged

    def _cleanup_staged_inputs(self, engine, container_name):
        cleanup_cmd = [
            engine,
            'exec',
            container_name,
            'sh',
            '-c',
            'rm -f /scan/inputs/spdx/vulnscout_stage_* /tmp/vulnscout_stage_*',
        ]
        result = subprocess.run(cleanup_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            stderr = (result.stderr or '').strip()
            if stderr:
                self.wrn(f'Could not clean staged VulnScout inputs: {stderr}')

    def _stop_vulnscout_container(self, args, best_effort=False):
        if args.vulnscout_cmd:
            stop_cmd = [args.vulnscout_cmd, '--stop']
            self.inf(f'Stopping VulnScout container with wrapper: {quote_sh_list(stop_cmd)}')
            env = os.environ.copy()
            self._set_vulnscout_image_env(env, args)
            try:
                subprocess.run(stop_cmd, env=env, check=True)
            except FileNotFoundError:
                if best_effort:
                    self.wrn(f'Could not find VulnScout command while stopping: {args.vulnscout_cmd}')
                    return
                self.die(
                    f'Could not find VulnScout command: {args.vulnscout_cmd}. '
                    f'Use --vulnscout-cmd with an absolute path, or use direct exec mode.'
                )
            except subprocess.CalledProcessError as e:
                if best_effort:
                    self.wrn(f'Failed to stop VulnScout container (wrapper): exit code {e.returncode}')
                    return
                self.die(f'Failed to stop VulnScout container: exit code {e.returncode}')
            return

        engine = self._resolve_container_engine(args.container_engine)
        rm_cmd = [engine, 'rm', '-f', args.container_name]
        self.inf(f'Stopping VulnScout container: {quote_sh_list(rm_cmd)}')
        result = subprocess.run(rm_cmd, capture_output=True, text=True)
        if result.returncode == 0:
            return
        stderr = (result.stderr or '').strip()
        stdout = (result.stdout or '').strip()
        details = stderr or stdout
        if 'No such container' in details:
            self.wrn(f'Container "{args.container_name}" is not running')
            return
        if best_effort:
            self.wrn(f'Failed to stop container "{args.container_name}": {details}')
            return
        self.die(f'Failed to stop container "{args.container_name}": {details}')

    def _run_west_spdx(self, args, build_dir, spdx_dir):
        requested_version = args.spdx_version

        cmd = [
            'west',
            'spdx',
            '--build-dir',
            build_dir,
            '--spdx-dir',
            spdx_dir,
            '--spdx-version',
            requested_version,
        ]
        if args.namespace_prefix:
            cmd.extend(['--namespace-prefix', args.namespace_prefix])
        if args.include_sdk:
            cmd.append('--include-sdk')
        if args.analyze_includes:
            cmd.append('--analyze-includes')

        self.inf(f'Generating SPDX {requested_version} SBOM with: {quote_sh_list(cmd)}')
        try:
            subprocess.run(cmd, check=True)
            return
        except subprocess.CalledProcessError as e:
            if requested_version == '3.1':
                self.wrn(
                    'west spdx failed for SPDX 3.1; retrying with SPDX 3.0. '
                    'Install a spdx-python-model build with v3_1 bindings to use SPDX 3.1.'
                )
            else:
                self.die(f'west spdx failed with exit code {e.returncode}')

        fallback_cmd = [
            'west',
            'spdx',
            '--build-dir',
            build_dir,
            '--spdx-dir',
            spdx_dir,
            '--spdx-version',
            '3.0',
        ]
        if args.namespace_prefix:
            fallback_cmd.extend(['--namespace-prefix', args.namespace_prefix])
        if args.include_sdk:
            fallback_cmd.append('--include-sdk')
        if args.analyze_includes:
            fallback_cmd.append('--analyze-includes')

        self.inf(f'Retrying SPDX generation with: {quote_sh_list(fallback_cmd)}')
        try:
            subprocess.run(fallback_cmd, check=True)
        except subprocess.CalledProcessError as e:
            self.die(f'west spdx failed with exit code {e.returncode}')

    def _resolve_spdx_files(self, explicit_files, spdx_dir):
        resolved = []

        for raw_path in explicit_files:
            file_path = os.path.abspath(raw_path)
            if not os.path.isfile(file_path):
                self.die(f'SPDX file does not exist: {file_path}')
            resolved.append(file_path)

        if resolved:
            return sorted(set(resolved))

        patterns = [
            os.path.join(spdx_dir, '*.jsonld'),
            os.path.join(spdx_dir, '*.spdx.json'),
            os.path.join(spdx_dir, '*.spdx'),
        ]

        for pattern in patterns:
            resolved.extend(glob.glob(pattern))

        resolved = sorted(set(os.path.abspath(p) for p in resolved if os.path.isfile(p)))
        return resolved

    def _run_vulnscout(self, args, spdx_files, data_dir):
        if args.dev and not args.vulnscout_cmd:
            self.die(
                '--dev is only supported with --vulnscout-cmd (wrapper mode). '
                'Direct container exec mode calls /scan/src/entrypoint.sh, which does not support --dev.'
            )

        vulnscout_args = [
            '--project',
            args.project,
            '--variant',
            args.variant,
        ]

        if args.vulnscout_cmd:
            for spdx_file in spdx_files:
                vulnscout_args.extend(['--add-spdx', spdx_file])
        else:
            engine = self._resolve_container_engine(args.container_engine)
            self._ensure_container_running(engine, args.container_name, args, data_dir)
            self._cleanup_staged_inputs(engine, args.container_name)
            staged_files = self._stage_spdx_files(engine, args.container_name, spdx_files)
            for spdx_file in staged_files:
                vulnscout_args.extend(['--add-spdx', spdx_file])

        if args.refresh_vulnerability_data:
            vulnscout_args.append('--refresh-vulnerability-data')
        if args.match_condition:
            vulnscout_args.extend(['--match-condition', args.match_condition])
        if args.serve:
            vulnscout_args.append('--serve')
        if args.dev:
            vulnscout_args.append('--dev')

        if args.vulnscout_cmd:
            vulnscout_cmd = [args.vulnscout_cmd] + vulnscout_args
        else:
            vulnscout_cmd = [
                engine,
                'exec',
            ]
            if args.serve:
                vulnscout_cmd.extend([
                    '-e',
                    'FLASK_RUN_HOST=0.0.0.0',
                    '-e',
                    'FLASK_RUN_PORT=7275',
                ])
            vulnscout_cmd.extend([
                args.container_name,
                '/scan/src/entrypoint.sh',
            ])
            vulnscout_cmd.extend(vulnscout_args)

        env = os.environ.copy()
        if args.vulnscout_cmd:
            self._set_vulnscout_image_env(env, args)

        pretty_files = ', '.join(pathlib.Path(f).name for f in spdx_files)
        self.inf(f'Importing SPDX files into VulnScout: {pretty_files}')
        self.inf(f'Running VulnScout command: {quote_sh_list(vulnscout_cmd)}')
        try:
            subprocess.run(vulnscout_cmd, env=env, check=True)
        except FileNotFoundError:
            self.die(
                f'Could not find VulnScout command: {args.vulnscout_cmd}. '
                f'Use --vulnscout-cmd with an absolute path, or use direct exec mode.'
            )
        except subprocess.CalledProcessError as e:
            self.die(f'VulnScout failed with exit code {e.returncode}')
