# Copyright (c) 2026
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
from collections.abc import Sequence
import glob
import os
import pathlib
import sys
import textwrap
import uuid

from west.commands import WestCommand
from west.util import quote_sh_list

from vulnscout_helpers import container, options
from vulnscout_helpers.process import DEFAULT_OPERATION_TIMEOUT, MANAGEMENT_TIMEOUT, VulnScoutError, run_command


VULNSCOUT_DESCRIPTION = """\
Generate/import a Zephyr SBOM or work with stored VulnScout results.

With no action, generate SPDX 3.0 using west spdx and import it into VulnScout.
This does not request vulnerability scanners; add --perform-scan to run them.
Build the application with CONFIG_BUILD_OUTPUT_META=y first.

Actions:
  report   Generate a report from stored data; no import or scan.
  export   Export stored data as SPDX, CycloneDX, or OpenVEX; no import or scan.
  stop     Stop and remove the container; no build directory required."""


class ZephyrVulnScout(WestCommand):
    def __init__(self) -> None:
        super().__init__('vulnscout', '', description=VULNSCOUT_DESCRIPTION)

    def do_add_parser(self, parser_adder):
        parser = parser_adder.add_parser(
            self.name,
            usage=(
                '%(prog)s -d BUILD_DIR [options]\n'
                '       %(prog)s {report,export} -d BUILD_DIR [options]\n'
                '       %(prog)s stop [container options]'
            ),
            description=self.description,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=textwrap.dedent(
                r"""
            Examples:
              Generate and import an SBOM:
                west vulnscout -d build

              Import, run all scanners, and start the web interface:
                west vulnscout -d build --perform-scan --serve

              Import existing SPDX files without regenerating them:
                west vulnscout -d build --no-generate --spdx-dir build/spdx

              Refresh stored vulnerability metadata without a new SBOM:
                west vulnscout -d build --refresh-vulnerability-data

              Generate an HTML report from stored data:
                west vulnscout report -d build --format html

              Export stored data as SPDX 2.3:
                west vulnscout export -d build --format spdx2

              Run scanners and exit with code 2 if a critical issue is found:
                west vulnscout -d build --perform-scan \
                  --match-condition 'cvss >= 9.0 and (pending or affected)'

              Use a custom image through the wrapper in development mode:
                west vulnscout -d build --vulnscout-cmd vulnscout \
                  --vulnscout-image sfl:custom --serve --dev

              Stop and remove the container:
                west vulnscout stop

            Notes:
              Reuse the same --project, --variant, and cache across commands.
              Report/export actions require direct Docker/Podman mode.
              --serve cannot be combined with --match-condition or --stop-after-run.
              Policy exit codes: 0 = no match, 2 = match, 1 = error.
              Direct-mode web settings: VULNSCOUT_ENV_FLASK_RUN_HOST (0.0.0.0)
              and VULNSCOUT_ENV_FLASK_RUN_PORT (7275), with native Flask fallbacks.
            """
            ).strip(),
        )

        scope = parser.add_argument_group('Build, project, and cache')
        sbom = parser.add_argument_group('SBOM generation and import')
        scanning = parser.add_argument_group('Vulnerability scanning and monitoring')
        web = parser.add_argument_group('Web interface')
        outputs = parser.add_argument_group('Reports and exports')
        container = parser.add_argument_group('Container and wrapper configuration')
        lifecycle = parser.add_argument_group('Container lifecycle')

        parser.add_argument(
            'action',
            nargs='?',
            choices=['stop', 'report', 'export'],
            help='optional action; omit to generate/import an SBOM',
        )
        scope.add_argument(
            '-d', '--build-dir',
            help='Zephyr build directory (required except for stop)',
        )
        sbom.add_argument(
            '--spdx-dir',
            help='SPDX output directory (default: <build-dir>/spdx)',
        )
        sbom.add_argument(
            '--spdx-version',
            choices=['3.0', '3.1'],
            default='3.0',
            help='generation version (default: 3.0; 3.1 needs spdx-python-model v3_1 bindings)',
        )
        sbom.add_argument(
            '--namespace-prefix',
            help='namespace prefix passed to west spdx',
        )
        sbom.add_argument(
            '--include-sdk',
            action='store_true',
            help='also generate SPDX document for SDK',
        )
        sbom.add_argument(
            '--analyze-includes',
            action='store_true',
            help='also analyze included header files',
        )
        sbom.add_argument(
            '--no-generate',
            action='store_true',
            help='skip generation but still import existing SPDX files',
        )
        lifecycle.add_argument(
            '--stop',
            action='store_true',
            help='alias for the stop action: stop/remove the container and exit',
        )
        lifecycle.add_argument(
            '--stop-after-run',
            action='store_true',
            help='stop/remove after completion, including a policy match (exit 2)',
        )
        sbom.add_argument(
            '--spdx-file',
            action='append',
            default=[],
            help='specific SPDX file to import (can be used multiple times)',
        )
        scope.add_argument(
            '--project',
            default='default',
            help='VulnScout project name (default: default)',
        )
        scope.add_argument(
            '--variant',
            default='default',
            help='variant within the project (default: default, not all variants)',
        )
        container.add_argument(
            '--vulnscout-cmd',
            help='use a wrapper instead of direct container mode (not for report/export)',
        )
        container.add_argument(
            '--vulnscout-image',
            help=(
                'container image repository or repository:tag override '
                '(when tag is omitted, VULNSCOUT_VERSION is used) '
                f'(default: {options.DEFAULT_VULNSCOUT_IMAGE})'
            ),
        )
        container.add_argument(
            '--container-engine',
            choices=['auto', 'docker', 'podman'],
            default='auto',
            help='container engine for direct exec mode (default: auto)',
        )
        container.add_argument(
            '--container-name',
            default='vulnscout',
            help='VulnScout container name for direct exec mode (default: vulnscout)',
        )
        scope.add_argument(
            '--vulnscout-data-dir',
            help=(
                'host directory mounted to /cache/vulnscout in direct mode '
                '(default: <build-dir>/../.vulnscout/cache)'
            ),
        )
        container.add_argument(
            '--timeout', type=options.positive_timeout, default=DEFAULT_OPERATION_TIMEOUT,
            metavar='SECONDS',
            help='deadline per finite SBOM/backend operation (default: 3600; maximum: 86400)',
        )
        scanning.add_argument(
            '--perform-scan',
            action='store_true',
            help='run all VulnScout scanners after import (passes --perform-scans all)',
        )
        web.add_argument(
            '--serve',
            action='store_true',
            help='start the web interface after processing (default: http://localhost:7275/)',
        )
        web.add_argument(
            '--dev',
            action='store_true',
            help='pass --dev to VulnScout (wrapper mode only)',
        )
        scanning.add_argument(
            '--refresh-vulnerability-data',
            action='store_true',
            help=(
                'refresh metadata; skip West SBOM generation unless '
                '--perform-scan is also set'
            ),
        )
        scanning.add_argument(
            '--match-condition',
            metavar='EXPRESSION',
            help='evaluate a quoted policy expression after processing (see exit codes below)',
        )
        outputs.add_argument(
            '--template',
            help='report only: installed template filename (default: summary.adoc)',
        )
        outputs.add_argument(
            '--format',
            choices=['html', 'pdf', *options.SBOM_EXPORT_FILES],
            help=(
                'report: html/pdf (default: template format); '
                'export: SBOM/OpenVEX format (default: spdx3)'
            ),
        )
        outputs.add_argument(
            '--output-dir',
            help=(
                'host output directory (report default: BUILD_DIR/vulnscout-reports; '
                'export default: BUILD_DIR/vulnscout-exports)'
            ),
        )

        return parser

    def do_run(self, args: argparse.Namespace, unknown_args: list[str]) -> None:
        try:
            self._run_workflow(args, unknown_args)
        except VulnScoutError as error:
            self.die(str(error))

    def _run_workflow(self, args: argparse.Namespace, unknown_args: list[str]) -> None:
        if unknown_args:
            self.die(f'Unexpected arguments: {unknown_args}')
        options.validate_options(args)
        output = options.stored_output_spec(args) if args.action in ('report', 'export') else None
        if args.action == 'stop' or args.stop:
            self._stop_vulnscout_container(args)
            return
        if not args.vulnscout_cmd:
            options.configured_web_settings()

        if not args.build_dir:
            self.die('Build directory not specified; call `west vulnscout --build-dir=BUILD_DIR`')

        build_dir = os.path.abspath(args.build_dir)
        spdx_dir = os.path.abspath(args.spdx_dir or os.path.join(build_dir, 'spdx'))

        if not os.path.isdir(build_dir):
            self.die(f'Build directory does not exist: {build_dir}')

        if output is not None:
            parameters, filename = output
            self._run_stored_output(args, build_dir, parameters, filename)
            if args.stop_after_run:
                self._stop_vulnscout_container(args)
            return

        refresh_only = args.refresh_vulnerability_data and not args.perform_scan
        spdx_files = []
        if not refresh_only:
            if not args.no_generate:
                self._run_west_spdx(args, build_dir, spdx_dir)

            spdx_files = self._resolve_spdx_files(args.spdx_file, spdx_dir)
            if not spdx_files:
                self.die(
                    f'No SPDX files found to import in {spdx_dir}. '
                    f'Expected *.jsonld, *.spdx.json, or *.spdx files.'
                )

        data_dir = options.resolve_data_dir(args, build_dir)

        try:
            exit_code = self._run_vulnscout(args, spdx_files, data_dir)
        except KeyboardInterrupt:
            if args.serve and not args.vulnscout_cmd:
                self.wrn('Interrupted by user; stopping VulnScout container')
                self._stop_vulnscout_container(args, best_effort=True)
                return
            raise

        if args.stop_after_run:
            self._stop_vulnscout_container(args)
        if exit_code == 2:
            raise SystemExit(2)

    def _container(self, args: argparse.Namespace) -> container.Container:
        return container.Container(
            container.resolve_engine(args.container_engine), args.container_name,
            info=self.inf, warn=self.wrn, debug=self.dbg, timeout=args.timeout,
        )

    def _resolve_export_variant_id(self, instance: container.Container, args: argparse.Namespace) -> str:
        interface = instance.check_processing_support()
        result = instance.run_backend(
            [*interface.cli, 'list-projects', '--json'],
            'Could not resolve export scope: list-projects',
            capture_output=True, timeout=MANAGEMENT_TIMEOUT,
        )
        return options.export_variant_id(result.stdout, args.project, args.variant)

    def _run_stored_output(
        self, args: argparse.Namespace, build_dir: str, parameters: list[str], filename: str,
    ) -> None:
        action = args.action
        instance = self._container(args)
        data_dir = options.resolve_data_dir(args, build_dir)
        instance.ensure_running(data_dir, options.resolve_image(args), *options.configured_web_settings())

        if action == 'export':
            scope = ['--variant-id', self._resolve_export_variant_id(instance, args)]
        else:
            scope = ['--project', args.project, '--variant', args.variant]
        temporary_dir = f'/tmp/vulnscout_{action}_{uuid.uuid4().hex}'
        output_dir = os.path.abspath(
            args.output_dir or os.path.join(build_dir, f'vulnscout-{action}s')
        )
        output_path = os.path.join(output_dir, filename)
        interface = instance.check_processing_support()
        command = [*interface.cli, *parameters, *scope, '--output-dir', temporary_dir]
        if action == 'report' and args.format:
            command.extend(['--format', args.format])
        self.inf(f'Generating VulnScout {action}: {quote_sh_list(command)}')
        try:
            instance.run_backend(
                command, f'{action.capitalize()} generation or retrieval',
                environment={'GENERATE_DOCUMENTS': ''},
            )
            os.makedirs(output_dir, exist_ok=True)
            run_command([
                instance.engine, 'cp', f'{instance.name}:{temporary_dir}/{filename}', output_path,
            ], f'{action.capitalize()} generation or retrieval', timeout=args.timeout)
        except OSError as e:
            raise VulnScoutError(f'Could not write {action} output: {e}') from e
        finally:
            instance.cleanup_directory(temporary_dir)
        self.inf(f'{action.capitalize()} written: {output_path}')

    def _stop_vulnscout_container(self, args: argparse.Namespace, best_effort: bool = False) -> None:
        if args.vulnscout_cmd:
            stop_cmd = [args.vulnscout_cmd, '--stop']
            self.inf(f'Stopping VulnScout container with wrapper: {quote_sh_list(stop_cmd)}')
            env = os.environ.copy()
            env.update(options.image_environment(args))
            try:
                run_command(stop_cmd, 'Stopping VulnScout container with wrapper', env=env)
            except VulnScoutError as error:
                if best_effort:
                    self.wrn(str(error))
                    return
                raise
            return

        self._container(args).stop(best_effort)

    def _run_west_spdx(self, args: argparse.Namespace, build_dir: str, spdx_dir: str) -> None:
        requested_version = args.spdx_version
        cmd = options.spdx_command(args, build_dir, spdx_dir, requested_version)
        self.inf(f'Generating SPDX {requested_version} SBOM with: {quote_sh_list(cmd)}')
        capture_output = requested_version == '3.1'
        try:
            result = run_command(cmd, 'west spdx', capture_output=capture_output, timeout=args.timeout)
            if capture_output:
                sys.stdout.write(result.stdout or '')
                sys.stderr.write(result.stderr or '')
            return
        except VulnScoutError as error:
            if capture_output and error.stdout:
                sys.stdout.write(error.stdout)
            if (
                requested_version == '3.1' and error.returncode == 1 and not error.timed_out
                and options.spdx31_bindings_unavailable(error.stderr)
            ):
                self.wrn(
                    'SPDX 3.1 Python bindings are unavailable; retrying with SPDX 3.0. '
                    'Install a spdx-python-model build with v3_1 bindings to use SPDX 3.1.'
                )
            else:
                raise
        fallback_cmd = options.spdx_command(args, build_dir, spdx_dir, '3.0')

        self.inf(f'Retrying SPDX generation with: {quote_sh_list(fallback_cmd)}')
        run_command(fallback_cmd, 'west spdx', timeout=args.timeout)

    def _resolve_spdx_files(self, explicit_files: Sequence[str], spdx_dir: str) -> list[str]:
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

    def _run_vulnscout(
        self, args: argparse.Namespace, spdx_files: Sequence[str], data_dir: str,
    ) -> int:
        accepted_codes = (0, 2) if args.match_condition else (0,)
        if args.vulnscout_cmd:
            command = [args.vulnscout_cmd, *options.processing_arguments(args, spdx_files)]
            if args.serve:
                command.append('--serve')
            if args.dev:
                command.append('--dev')
            env = os.environ.copy()
            env.update(options.image_environment(args))
            self.inf(f'Running VulnScout command: {quote_sh_list(command)}')
            result = run_command(
                command, 'VulnScout', env=env, accepted_codes=accepted_codes,
                timeout=None if args.serve else args.timeout,
            )
            return 2 if result.returncode == 2 else 0

        instance = self._container(args)
        instance.ensure_running(data_dir, options.resolve_image(args), *options.configured_web_settings())
        interface = instance.check_processing_support()
        if args.serve:
            self.inf(
                'Processing before starting the web interface; an existing web server is left running'
            )
        with instance.input_workspace() as directory:
            staged = instance.stage_files(spdx_files, directory) if spdx_files else []
            self.inf(f'Processing VulnScout project "{args.project}", variant "{args.variant}"')
            exit_code = instance.run_processing(
                options.processing_arguments(args, staged), directory, accepted_codes=accepted_codes,
            )
        if args.serve:
            host, port = options.configured_web_settings()
            serve_command = container.container_exec(
                instance.engine, instance.name,
                [*interface.entrypoint, '--project', args.project, '--variant', args.variant, '--serve'],
                environment={
                    'VULNSCOUT_INPUTS_DIR': f'{directory}/inputs',
                    'FLASK_RUN_HOST': host, 'FLASK_RUN_PORT': port,
                },
                workdir=interface.workdir,
            )
            self.inf(f'Starting web interface: {quote_sh_list(serve_command)}')
            run_command(serve_command, 'VulnScout web interface', timeout=None)
        return 2 if exit_code == 2 else 0
