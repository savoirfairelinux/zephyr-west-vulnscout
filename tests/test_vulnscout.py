# Copyright (c) 2026
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import contextlib
import importlib
import importlib.util
import io
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch


COMMAND_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / 'scripts' / 'west_commands' / 'vulnscout.py'
)
SPEC = importlib.util.spec_from_file_location('vulnscout', COMMAND_PATH)
vulnscout = importlib.util.module_from_spec(SPEC)
with patch.object(sys, 'path', [str(COMMAND_PATH.parent), *sys.path]):
    SPEC.loader.exec_module(vulnscout)

from vulnscout_helpers import backend, container as containers, options as config, process


INTERFACE_DATA = {
    'version': 1, 'features': ['isolated-inputs', 'python-fcntl'],
    'entrypoint': ['/scan/src/entrypoint.sh'],
    'cli': ['flask', '--app', 'src.bin.webapp'], 'python': ['python'], 'workdir': '/scan',
}
INTERFACE = backend.parse_interface(json.dumps(INTERFACE_DATA))


def fail(message):
    raise RuntimeError(message)


class VulnScoutCommandTests(unittest.TestCase):
    def setUp(self):
        web_env = patch.dict(os.environ)
        web_env.start()
        self.addCleanup(web_env.stop)
        os.environ.pop('FLASK_RUN_HOST', None)
        os.environ.pop('FLASK_RUN_PORT', None)
        os.environ.pop('VULNSCOUT_ENV_FLASK_RUN_HOST', None)
        os.environ.pop('VULNSCOUT_ENV_FLASK_RUN_PORT', None)
        for name, value in [
            ('VULNSCOUT_ENV_FLASK_RUN_HOST', '0.0.0.0'),
            ('VULNSCOUT_ENV_FLASK_RUN_PORT', '7275'),
        ]:
            setting = patch.object(config, name, value)
            setting.start()
            self.addCleanup(setting.stop)
        self.command = vulnscout.ZephyrVulnScout()
        info = patch.object(self.command, 'inf')
        info.start()
        self.addCleanup(info.stop)
        self.parser = argparse.ArgumentParser()
        self.command.do_add_parser(self.parser.add_subparsers())
        self.interface_patch = patch.object(
            containers.Container, 'check_processing_support', return_value=INTERFACE,
        )
        self.interface_patch.start()
        self.addCleanup(self.interface_patch.stop)

    def parse(self, *arguments):
        return self.parser.parse_args(['vulnscout', *arguments])

    def container(self, engine='podman', name='demo'):
        return containers.Container(
            engine, name, info=self.command.inf, warn=self.command.wrn, debug=self.command.dbg,
        )

    def test_west_loads_command_from_an_unrelated_working_directory(self):
        script = """
import argparse
import sys
from west.commands import _ExtFactory

command = _ExtFactory(sys.argv[1], 'vulnscout', 'ZephyrVulnScout')()
root = argparse.ArgumentParser(prog='west')
parser = command.do_add_parser(root.add_subparsers())
print(parser.format_help())
"""
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, '-I', '-c', script, str(COMMAND_PATH)],
                cwd=directory, capture_output=True, text=True, timeout=15,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Reports and exports', result.stdout)
        self.assertIn('Container lifecycle', result.stdout)

    def test_helpers_import_independently_without_west(self):
        script = """
import sys
sys.path.insert(0, sys.argv[1])
sys.modules['west'] = None
from vulnscout_helpers import container, options, process
assert options.web_server_settings('0.0.0.0', '7275') == ('0.0.0.0', '7275')
assert container.container_exec('podman', 'demo', ['true']) == ['podman', 'exec', 'demo', 'true']
assert issubclass(process.VulnScoutError, RuntimeError)
"""
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, '-I', '-c', script, str(COMMAND_PATH.parent)],
                cwd=directory, capture_output=True, text=True, timeout=15,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_image_configuration_preserves_registry_ports_tags_and_wrapper_aliases(self):
        for image, expected in [
            (None, config.DEFAULT_VULNSCOUT_IMAGE),
            (' ', config.DEFAULT_VULNSCOUT_IMAGE),
            ('registry.example:5000/team/vulnscout', f'registry.example:5000/team/vulnscout:{config.VULNSCOUT_VERSION}'),
            ('registry.example:5000/team/vulnscout:custom', 'registry.example:5000/team/vulnscout:custom'),
        ]:
            with self.subTest(image=image):
                args = self.parse(*(['--vulnscout-image', image] if image is not None else []))
                self.assertEqual(config.resolve_image(args), expected)
                environment = config.image_environment(args)
                self.assertEqual(environment['VULNSCOUT_IMAGE'], expected)
                self.assertEqual(environment['VULNSCOUT_VERSION'], environment['VULNSCOT_VERSION'])

    def test_container_engine_selection_and_errors(self):
        for available, expected in [
            ({'podman': '/bin/podman', 'docker': '/bin/docker'}, 'podman'),
            ({'docker': '/bin/docker'}, 'docker'),
        ]:
            with self.subTest(available=available), patch.object(shutil, 'which', side_effect=available.get):
                self.assertEqual(containers.resolve_engine('auto'), expected)
        with patch.object(shutil, 'which', return_value=None):
            with self.assertRaisesRegex(process.VulnScoutError, 'Requested container engine is not available'):
                containers.resolve_engine('podman')
            with self.assertRaisesRegex(process.VulnScoutError, 'Could not find podman or docker'):
                containers.resolve_engine('auto')

    def test_help_has_a_short_synopsis_and_feature_groups(self):
        with patch.dict(os.environ, {'COLUMNS': '80'}):
            root = argparse.ArgumentParser(prog='west')
            parser = self.command.do_add_parser(root.add_subparsers())
            help_text = parser.format_help()
        synopsis = help_text.split('\n\n', 1)[0]
        self.assertEqual(synopsis.splitlines(), [
            'usage: west vulnscout -d BUILD_DIR [options]',
            '       west vulnscout {report,export} -d BUILD_DIR [options]',
            '       west vulnscout stop [container options]',
        ])
        groups = [
            ('Build, project, and cache', '--project'),
            ('SBOM generation and import', '--no-generate'),
            ('Vulnerability scanning and monitoring', '--match-condition'),
            ('Web interface', '--serve'),
            ('Reports and exports', '--template'),
            ('Container and wrapper configuration', '--vulnscout-cmd'),
            ('Container lifecycle', '--stop-after-run'),
        ]
        for index, (title, option) in enumerate(groups):
            with self.subTest(group=title):
                section = help_text.split(f'{title}:\n', 1)[1]
                next_title = groups[index + 1][0] if index + 1 < len(groups) else 'Examples'
                section = section.split(f'\n{next_title}:\n', 1)[0]
                self.assertIn(option, section)
        self.assertIn('does not request vulnerability scanners', help_text)
        self.assertIn('Policy exit codes: 0 = no match, 2 = match, 1 = error.', help_text)
        for line in help_text.splitlines():
            self.assertLessEqual(len(line), 80, line)

    def test_help_examples_are_aligned_and_parseable(self):
        parser = self.command.do_add_parser(argparse.ArgumentParser(prog='west').add_subparsers())
        help_text = parser.format_help()
        examples = help_text.split('Examples:\n', 1)[1].split('\nNotes:\n', 1)[0]
        self.assertIn(
            '    west vulnscout -d build --vulnscout-cmd vulnscout \\\n'
            '      --vulnscout-image sfl:custom --serve --dev',
            examples,
        )
        commands = []
        pending = ''
        for line in examples.splitlines():
            if not line.strip() or not (pending or line.strip().startswith('west vulnscout ')):
                continue
            self.assertTrue(line.startswith('      ' if pending else '    west '), line)
            pending += line.strip()
            if pending.endswith('\\'):
                pending = pending[:-1] + ' '
            else:
                commands.append(self.parse(*shlex.split(pending)[2:]))
                pending = ''
        self.assertFalse(pending)
        self.assertEqual(len(commands), 9)
        self.assertEqual([args.action for args in commands],
                         [None, None, None, None, 'report', 'export', None, None, 'stop'])
        self.assertTrue(commands[1].perform_scan)
        self.assertTrue(commands[1].serve)
        self.assertTrue(commands[2].no_generate)
        self.assertTrue(commands[3].refresh_vulnerability_data)
        self.assertEqual(commands[4].format, 'html')
        self.assertEqual(commands[5].format, 'spdx2')
        self.assertEqual(commands[6].match_condition, 'cvss >= 9.0 and (pending or affected)')
        self.assertEqual(commands[7].vulnscout_image, 'sfl:custom')
        self.assertTrue(commands[7].dev)
        self.assertIsNone(commands[8].build_dir)

    def test_stop_forms_skip_build_and_import(self):
        for arguments in [('stop',), ('--stop',), ('stop', '--stop')]:
            with self.subTest(arguments=arguments):
                args = self.parse(*arguments)
                with (
                    patch.object(self.command, '_stop_vulnscout_container') as stop,
                    patch.object(self.command, '_run_west_spdx') as generate,
                    patch.object(self.command, '_run_vulnscout') as scan,
                ):
                    self.command.do_run(args, [])
                stop.assert_called_once_with(args)
                generate.assert_not_called()
                scan.assert_not_called()

    def test_stop_honors_engine_and_container(self):
        for arguments in [
            ('stop', '--container-engine', 'podman', '--container-name', 'demo'),
            ('--container-engine', 'podman', '--container-name', 'demo', 'stop'),
            ('--stop', '--container-engine', 'podman', '--container-name', 'demo'),
        ]:
            with self.subTest(arguments=arguments):
                args = self.parse(*arguments)
                with (
                    patch.object(shutil, 'which', return_value='/usr/bin/podman'),
                    patch.object(subprocess, 'run') as run,
                ):
                    run.return_value = subprocess.CompletedProcess([], 0, '', '')
                    self.command.do_run(args, [])
                run.assert_called_once_with(
                    ['podman', 'rm', '-f', 'demo'],
                    check=True, capture_output=True, text=True, env=None, timeout=30,
                )

    def test_stop_honors_wrapper(self):
        args = self.parse('stop', '--vulnscout-cmd', '/demo/vulnscout')
        with patch.object(subprocess, 'run') as run:
            self.command.do_run(args, [])
        self.assertEqual(run.call_args.args[0], ['/demo/vulnscout', '--stop'])
        self.assertTrue(run.call_args.kwargs['check'])

    def test_unknown_action_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.parse('restart')

    def test_scan_flags_in_container_and_wrapper_modes(self):
        for wrapper in [False, True]:
            for perform_scan in [False, True]:
                for serve in [False, True]:
                    with self.subTest(wrapper=wrapper, perform_scan=perform_scan, serve=serve):
                        options = ['--project', 'demo', '--variant', 'native']
                        if wrapper:
                            options.extend(['--vulnscout-cmd', '/demo/vulnscout'])
                        if perform_scan:
                            options.append('--perform-scan')
                        if serve:
                            options.append('--serve')
                        args = self.parse(*options)
                        with (
                            patch.object(containers, 'resolve_engine',
                                         return_value='podman'),
                            patch.object(containers.Container, 'ensure_running'),
                            patch.object(containers.Container, 'check_processing_support', return_value=INTERFACE),
                            patch.object(containers.Container, 'input_workspace',
                                         return_value=contextlib.nullcontext('/tmp/west-inputs')),
                            patch.object(containers.Container, 'stage_files',
                                         return_value=['/tmp/app.spdx.json']),
                            patch.object(subprocess, 'run') as run,
                        ):
                            self.command._run_vulnscout(args, ['/demo/app.jsonld'], '/cache')
                        if wrapper:
                            expected = ['/demo/vulnscout']
                            spdx_file = '/demo/app.jsonld'
                        else:
                            expected = [
                                'podman', 'exec', '-e', 'VULNSCOUT_INPUTS_DIR=/tmp/west-inputs/inputs',
                                '-w', '/scan', 'vulnscout', 'python', '-c', containers.PROCESSING_LOCK_PROGRAM,
                                '/cache/vulnscout/.west-vulnscout.lock', '3600', '/scan/src/entrypoint.sh',
                            ]
                            spdx_file = '/tmp/app.spdx.json'
                        expected.extend([
                            '--project', 'demo', '--variant', 'native',
                            '--add-spdx', spdx_file,
                        ])
                        if perform_scan:
                            expected.extend(['--perform-scans', 'all'])
                        if wrapper and serve:
                            expected.append('--serve')
                        self.assertEqual(run.call_count, 2 if serve and not wrapper else 1)
                        self.assertEqual(run.call_args_list[0].args[0], expected)
                        self.assertTrue(run.call_args.kwargs['check'])
                        if serve and not wrapper:
                            followup = run.call_args_list[1].args[0]
                            self.assertEqual(followup[-5:], [
                                '--project', 'demo', '--variant', 'native', '--serve',
                            ])
                            self.assertNotIn('--perform-scans', followup)
                            self.assertNotIn('--add-spdx', followup)
                            self.assertNotIn(containers.PROCESSING_LOCK_PROGRAM, followup)

    def test_default_action_still_generates_and_imports(self):
        with tempfile.TemporaryDirectory() as build_dir:
            args = self.parse('-d', build_dir)
            self.assertIsNone(args.action)
            spdx_dir = str(pathlib.Path(build_dir) / 'spdx')
            files = [str(pathlib.Path(spdx_dir) / 'app.jsonld')]
            with (
                patch.object(self.command, '_stop_vulnscout_container') as stop,
                patch.object(self.command, '_run_west_spdx') as generate,
                patch.object(self.command, '_resolve_spdx_files', return_value=files),
                patch.object(self.command, '_run_vulnscout') as scan,
            ):
                self.command.do_run(args, [])
            stop.assert_not_called()
            generate.assert_called_once_with(args, build_dir, spdx_dir)
            scan.assert_called_once_with(
                args, files, config.resolve_data_dir(args, build_dir)
            )

    def test_new_container_uses_native_web_settings(self):
        for engine in ['podman', 'docker']:
            for port in ['7275', '8080']:
                with (
                    self.subTest(engine=engine, port=port),
                    tempfile.TemporaryDirectory() as data_dir,
                    patch.object(config, 'VULNSCOUT_ENV_FLASK_RUN_PORT', port),
                    patch.object(containers.Container, 'state', return_value=None),
                    patch.object(containers.Container, 'data_mount', return_value=data_dir),
                    patch.object(containers.Container, 'wait_ready') as ready,
                    patch.object(subprocess, 'run') as run,
                ):
                    args = self.parse('--container-name', 'web-settings')
                    self.container(engine, args.container_name).ensure_running(
                        data_dir, config.resolve_image(args), *config.configured_web_settings(),
                    )
                    run.assert_called_once_with([
                        engine, 'run', '-d', '--name', 'web-settings',
                        '-p', f'{port}:{port}',
                        '-e', 'FLASK_RUN_HOST=0.0.0.0', '-e', f'FLASK_RUN_PORT={port}',
                        '-v', f'{data_dir}:/cache/vulnscout',
                        config.DEFAULT_VULNSCOUT_IMAGE, 'daemon',
                    ], check=True, capture_output=False, text=True, env=None, timeout=300)
                    ready.assert_called_once_with()

    def test_serve_forwards_native_web_settings(self):
        for host in ['0.0.0.0', '::', '127.0.0.1']:
            with (
                self.subTest(host=host),
                patch.object(config, 'VULNSCOUT_ENV_FLASK_RUN_HOST', host),
                patch.object(config, 'VULNSCOUT_ENV_FLASK_RUN_PORT', '8080'),
                patch.object(containers, 'resolve_engine', return_value='podman'),
                patch.object(containers.Container, 'ensure_running'),
                patch.object(containers.Container, 'check_processing_support', return_value=INTERFACE),
                patch.object(containers.Container, 'input_workspace',
                             return_value=contextlib.nullcontext('/tmp/west-inputs')),
                patch.object(subprocess, 'run') as run,
            ):
                args = self.parse('--serve', '--refresh-vulnerability-data')
                self.command._run_vulnscout(args, [], '/cache')
                self.assertEqual(run.call_args.args[0], [
                    'podman', 'exec', '-e', 'VULNSCOUT_INPUTS_DIR=/tmp/west-inputs/inputs',
                    '-e', f'FLASK_RUN_HOST={host}', '-e', 'FLASK_RUN_PORT=8080',
                    '-w', '/scan', 'vulnscout', '/scan/src/entrypoint.sh',
                    '--project', 'default', '--variant', 'default',
                    '--serve',
                ])
                self.assertEqual(run.call_count, 2)
                self.assertIn('--refresh-vulnerability-data', run.call_args_list[0].args[0])
                self.assertIsNone(run.call_args.kwargs['timeout'])

    def test_invalid_native_web_settings_are_rejected(self):
        cases = [
            ('VULNSCOUT_ENV_FLASK_RUN_PORT', port)
            for port in ['', '0', '-1', '65536', '8080/tcp', '1.5']
        ] + [('VULNSCOUT_ENV_FLASK_RUN_HOST', ''), ('VULNSCOUT_ENV_FLASK_RUN_HOST', '   ')]
        for name, value in cases:
            with (
                self.subTest(name=name, value=value),
                patch.object(config, name, value),
                patch.object(self.command, 'die', side_effect=fail),
            ):
                with self.assertRaisesRegex(RuntimeError, 'FLASK_RUN_'):
                    config.configured_web_settings()

    def test_web_environment_defaults_aliases_and_precedence(self):
        cases = [
            ({}, ('0.0.0.0', '7275')),
            ({'FLASK_RUN_HOST': '::', 'FLASK_RUN_PORT': '8080'}, ('::', '8080')),
            ({
                'VULNSCOUT_ENV_FLASK_RUN_HOST': '0.0.0.0',
                'VULNSCOUT_ENV_FLASK_RUN_PORT': '9090',
            }, ('0.0.0.0', '9090')),
            ({
                'VULNSCOUT_ENV_FLASK_RUN_HOST': '0.0.0.0',
                'VULNSCOUT_ENV_FLASK_RUN_PORT': '9090',
                'FLASK_RUN_HOST': '127.0.0.1', 'FLASK_RUN_PORT': '8080',
            }, ('0.0.0.0', '9090')),
        ]
        self.addCleanup(importlib.reload, config)
        for settings, expected in cases:
            with self.subTest(settings=settings), patch.dict(os.environ, settings):
                importlib.reload(config)
                self.assertEqual(config.configured_web_settings(), expected)

    def test_refresh_only_skips_generation_and_import(self):
        for wrapper in [False, True]:
            for serve in [False, True]:
                with self.subTest(wrapper=wrapper, serve=serve), tempfile.TemporaryDirectory() as build_dir:
                    options = [
                        '-d', build_dir, '--project', 'demo', '--variant', 'native',
                        '--refresh-vulnerability-data',
                    ]
                    if wrapper:
                        options.extend(['--vulnscout-cmd', '/demo/vulnscout'])
                    if serve:
                        options.append('--serve')
                    args = self.parse(*options)
                    with (
                        patch.object(self.command, '_run_west_spdx') as generate,
                        patch.object(self.command, '_resolve_spdx_files') as resolve,
                        patch.object(containers, 'resolve_engine',
                                     return_value='podman'),
                        patch.object(containers.Container, 'ensure_running'),
                        patch.object(containers.Container, 'check_processing_support', return_value=INTERFACE),
                        patch.object(containers.Container, 'input_workspace',
                                     return_value=contextlib.nullcontext('/tmp/west-inputs')),
                        patch.object(containers.Container, 'stage_files') as stage,
                        patch.object(subprocess, 'run') as run,
                    ):
                        self.command.do_run(args, [])
                    generate.assert_not_called()
                    resolve.assert_not_called()
                    stage.assert_not_called()
                    expected = ['/demo/vulnscout'] if wrapper else ['podman', 'exec']
                    if not wrapper:
                        expected.extend([
                            '-e', 'VULNSCOUT_INPUTS_DIR=/tmp/west-inputs/inputs',
                            '-w', '/scan', 'vulnscout', 'python', '-c', containers.PROCESSING_LOCK_PROGRAM,
                            '/cache/vulnscout/.west-vulnscout.lock', '3600', '/scan/src/entrypoint.sh',
                        ])
                    expected.extend([
                        '--project', 'demo', '--variant', 'native',
                        '--refresh-vulnerability-data',
                    ])
                    if serve and wrapper:
                        expected.append('--serve')
                    self.assertEqual(run.call_count, 2 if serve and not wrapper else 1)
                    self.assertEqual(run.call_args_list[0].args[0], expected)

    def test_scan_with_refresh_still_generates_and_imports(self):
        with tempfile.TemporaryDirectory() as build_dir:
            args = self.parse(
                '-d', build_dir, '--perform-scan', '--refresh-vulnerability-data',
                '--vulnscout-cmd', '/demo/vulnscout',
            )
            files = [str(pathlib.Path(build_dir) / 'spdx' / 'app.jsonld')]
            with (
                patch.object(self.command, '_run_west_spdx') as generate,
                patch.object(self.command, '_resolve_spdx_files', return_value=files),
                patch.object(subprocess, 'run') as run,
            ):
                self.command.do_run(args, [])
            generate.assert_called_once()
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0], [
                '/demo/vulnscout', '--project', 'default', '--variant', 'default',
                '--add-spdx', files[0], '--perform-scans', 'all',
                '--refresh-vulnerability-data',
            ])

    def test_match_condition_forwarding_and_exit_status(self):
        condition = '(cvss >= 9.0 or epss >= 50%) and (pending or affected)'
        for wrapper in [False, True]:
            for status in [0, 1, 2]:
                with (
                    self.subTest(wrapper=wrapper, status=status),
                    patch.object(containers, 'resolve_engine', return_value='podman'),
                    patch.object(containers.Container, 'ensure_running'),
                    patch.object(containers.Container, 'check_processing_support', return_value=INTERFACE),
                    patch.object(containers.Container, 'input_workspace',
                                 return_value=contextlib.nullcontext('/tmp/west-inputs')),
                    patch.object(self.command, 'die', side_effect=fail),
                    patch.object(subprocess, 'run') as run,
                ):
                    options = ['--match-condition', condition, '--project', 'zephyr', '--variant', 'native']
                    if wrapper:
                        options.extend(['--vulnscout-cmd', '/demo/vulnscout'])
                    args = self.parse(*options)
                    if status:
                        run.side_effect = subprocess.CalledProcessError(status, 'vulnscout')
                    if status == 1:
                        with self.assertRaisesRegex(RuntimeError, 'exit code 1'):
                            self.command._run_vulnscout(args, [], '/cache')
                    else:
                        self.assertEqual(self.command._run_vulnscout(args, [], '/cache'), status)
                    command = run.call_args.args[0]
                    self.assertEqual(command[-2:], ['--match-condition', condition])
                    self.assertIn('zephyr', command)
                    self.assertIn('native', command)

    def test_exit_two_without_a_match_condition_is_an_error(self):
        with (
            patch.object(containers, 'resolve_engine', return_value='podman'),
            patch.object(containers.Container, 'ensure_running'),
            patch.object(containers.Container, 'check_processing_support', return_value=INTERFACE),
            patch.object(containers.Container, 'input_workspace',
                         return_value=contextlib.nullcontext('/tmp/west-inputs')),
            patch.object(self.command, 'die', side_effect=fail),
            patch.object(subprocess, 'run', side_effect=subprocess.CalledProcessError(2, 'vulnscout')),
        ):
            with self.assertRaisesRegex(RuntimeError, 'exit code 2'):
                self.command._run_vulnscout(self.parse(), [], '/cache')

    def test_refresh_condition_skips_import_and_stops_before_propagating_matches(self):
        with tempfile.TemporaryDirectory() as build_dir:
            for status in [0, 2]:
                for stop_requested in [False, True]:
                    with self.subTest(status=status, stop=stop_requested):
                        options = [
                            '-d', build_dir, '--refresh-vulnerability-data',
                            '--match-condition', 'cvss >= 9.0',
                        ]
                        if stop_requested:
                            options.append('--stop-after-run')
                        args = self.parse(*options)
                        with (
                            patch.object(self.command, '_run_west_spdx') as generate,
                            patch.object(self.command, '_resolve_spdx_files') as resolve,
                            patch.object(self.command, '_run_vulnscout', return_value=status) as scan,
                            patch.object(self.command, '_stop_vulnscout_container') as stop,
                        ):
                            if status == 2:
                                with self.assertRaises(SystemExit) as caught:
                                    self.command.do_run(args, [])
                                self.assertEqual(caught.exception.code, 2)
                            else:
                                self.command.do_run(args, [])
                        generate.assert_not_called()
                        resolve.assert_not_called()
                        scan.assert_called_once_with(
                            args, [], config.resolve_data_dir(args, build_dir),
                        )
                        if stop_requested:
                            stop.assert_called_once_with(args)
                        else:
                            stop.assert_not_called()

    def test_import_with_condition_preserves_generation_and_match_exit(self):
        with tempfile.TemporaryDirectory() as build_dir:
            args = self.parse('-d', build_dir, '--match-condition', 'pending')
            files = [str(pathlib.Path(build_dir) / 'spdx' / 'app.jsonld')]
            with (
                patch.object(self.command, '_run_west_spdx') as generate,
                patch.object(self.command, '_resolve_spdx_files', return_value=files),
                patch.object(self.command, '_run_vulnscout', return_value=2) as scan,
            ):
                with self.assertRaises(SystemExit) as caught:
                    self.command.do_run(args, [])
                self.assertEqual(caught.exception.code, 2)
            generate.assert_called_once()
            self.assertEqual(scan.call_args.args[1], files)

    def test_empty_conditions_and_serve_are_rejected_before_generation(self):
        cases = [
            ['--match-condition', ''], ['--match-condition', '   '],
            ['--match-condition', 'pending', '--serve'],
        ]
        for options in cases:
            with (
                self.subTest(options=options),
                patch.object(self.command, 'die', side_effect=fail),
                patch.object(self.command, '_run_west_spdx') as generate,
                patch.object(self.command, '_run_vulnscout') as scan,
            ):
                with self.assertRaisesRegex(RuntimeError, '--match-condition'):
                    self.command.do_run(self.parse(*options), [])
                generate.assert_not_called()
                scan.assert_not_called()

    def test_report_skips_import_and_copies_only_the_requested_report(self):
        for engine in ['podman', 'docker']:
            for output_format in [None, 'html', 'pdf']:
                with self.subTest(engine=engine, format=output_format), tempfile.TemporaryDirectory() as build_dir:
                    options = [
                        'report', '-d', build_dir, '--container-engine', engine,
                        '--container-name', 'demo', '--project', 'zephyr',
                        '--variant', 'native', '--template', 'all_assessments.adoc',
                    ]
                    if output_format:
                        options.extend(['--format', output_format, '--output-dir', build_dir])
                    args = self.parse(*options)
                    cache = config.resolve_data_dir(args, build_dir)
                    report_dir = '/tmp/vulnscout_report_00000000000000000000000000000001'
                    filename = 'all_assessments.adoc' + (f'.{output_format}' if output_format else '')
                    output_dir = build_dir if output_format else str(pathlib.Path(build_dir) / 'vulnscout-reports')
                    with (
                        patch.object(containers, 'resolve_engine', return_value=engine),
                        patch.object(containers.Container, 'ensure_running') as ensure,
                        patch.object(containers.Container, 'data_mount', return_value=cache),
                        patch.object(self.command, '_run_west_spdx') as generate,
                        patch.object(self.command, '_resolve_spdx_files') as resolve,
                        patch.object(self.command, '_run_vulnscout') as scan,
                        patch.object(uuid, 'uuid4', return_value=uuid.UUID(int=1)),
                        patch.object(subprocess, 'run') as run,
                    ):
                        run.return_value = subprocess.CompletedProcess([], 0, '', '')
                        self.command.do_run(args, [])
                    ensure.assert_called_once_with(cache, config.DEFAULT_VULNSCOUT_IMAGE, '0.0.0.0', '7275')
                    generate.assert_not_called()
                    resolve.assert_not_called()
                    scan.assert_not_called()
                    expected = [
                        engine, 'exec', '-e', 'GENERATE_DOCUMENTS=', '-w', '/scan',
                        'demo', 'python', '-c', containers.PROCESSING_LOCK_PROGRAM, '', '3600',
                        'flask', '--app', 'src.bin.webapp',
                        'report', 'all_assessments.adoc', '--project', 'zephyr',
                        '--variant', 'native', '--output-dir', report_dir,
                    ]
                    if output_format:
                        expected.extend(['--format', output_format])
                    self.assertEqual(run.call_count, 3)
                    self.assertEqual(run.call_args_list[0].args[0], expected)
                    self.assertTrue(run.call_args_list[0].kwargs['check'])
                    self.assertEqual(run.call_args_list[1].args[0], [
                        engine, 'cp', f'demo:{report_dir}/{filename}',
                        str(pathlib.Path(output_dir) / filename),
                    ])
                    self.assertTrue(run.call_args_list[1].kwargs['check'])
                    self.assertEqual(run.call_args_list[2].args[0], [
                        engine, 'exec', 'demo', 'rm', '-rf', '--', report_dir,
                    ])

    def test_report_defaults_and_stop_after_success(self):
        with tempfile.TemporaryDirectory() as build_dir:
            args = self.parse('report', '-d', build_dir, '--stop-after-run')
            cache = config.resolve_data_dir(args, build_dir)
            with (
                patch.object(containers, 'resolve_engine', return_value='podman'),
                patch.object(containers.Container, 'ensure_running'),
                patch.object(containers.Container, 'data_mount', return_value=cache),
                patch.object(self.command, '_stop_vulnscout_container') as stop,
                patch.object(subprocess, 'run') as run,
            ):
                run.return_value = subprocess.CompletedProcess([], 0, '', '')
                self.command.do_run(args, [])
            self.assertIn('summary.adoc', run.call_args_list[0].args[0])
            stop.assert_called_once_with(args)

    def test_report_rejects_conflicting_options_and_template_paths(self):
        cases = [
            ['--stop'], ['--serve'], ['--perform-scan'], ['--refresh-vulnerability-data'],
            ['--no-generate'], ['--spdx-file', 'app.jsonld'],
            ['--vulnscout-cmd', '/demo/vulnscout'],
            ['--template', '../summary.adoc'], ['--template', '/tmp/summary.adoc'],
            ['--template', ''], ['--template', 'summary.html', '--format', 'pdf'],
        ]
        with tempfile.TemporaryDirectory() as build_dir:
            for options in cases:
                with (
                    self.subTest(options=options),
                    patch.object(self.command, 'die', side_effect=fail) as die,
                    patch.object(containers, 'resolve_engine') as engine,
                ):
                    with self.assertRaises(RuntimeError):
                        self.command.do_run(self.parse('report', '-d', build_dir, *options), [])
                    die.assert_called_once()
                    engine.assert_not_called()

    def test_report_options_require_report_action(self):
        for options in [
            ['--template', 'summary.adoc'], ['--format', 'html'], ['--output-dir', 'reports'],
        ]:
            with (
                self.subTest(options=options),
                patch.object(self.command, 'die', side_effect=fail),
            ):
                with self.assertRaisesRegex(RuntimeError, 'require `west vulnscout report`'):
                    self.command.do_run(self.parse(*options), [])

    def test_report_rejects_a_different_or_unmounted_database(self):
        with tempfile.TemporaryDirectory() as build_dir:
            for mounted_dir in ['', '/another/cache']:
                with (
                    self.subTest(mount=mounted_dir),
                    patch.object(containers, 'resolve_engine', return_value='podman'),
                    patch.object(containers.Container, 'state', return_value='running'),
                    patch.object(containers.Container, 'data_mount', return_value=mounted_dir),
                    patch.object(self.command, 'die', side_effect=fail),
                    patch.object(subprocess, 'run') as run,
                ):
                    with self.assertRaisesRegex(RuntimeError, 'must mount the selected cache'):
                        self.command.do_run(self.parse('report', '-d', build_dir), [])
                    run.assert_not_called()

    def test_report_failures_are_explicit_and_always_clean_up(self):
        with tempfile.TemporaryDirectory() as build_dir:
            for fail_copy in [False, True]:
                args = self.parse('report', '-d', build_dir, '--stop-after-run')
                cache = config.resolve_data_dir(args, build_dir)
                success = subprocess.CompletedProcess([], 0, '', '')
                results = ([success] if fail_copy else []) + [
                    subprocess.CalledProcessError(1, 'report'), success,
                ]
                with (
                    self.subTest(fail_copy=fail_copy),
                    patch.object(containers, 'resolve_engine', return_value='podman'),
                    patch.object(containers.Container, 'ensure_running'),
                    patch.object(containers.Container, 'data_mount', return_value=cache),
                    patch.object(self.command, '_stop_vulnscout_container') as stop,
                    patch.object(self.command, 'die', side_effect=fail),
                    patch.object(subprocess, 'run', side_effect=results) as run,
                ):
                    with self.assertRaisesRegex(RuntimeError, 'generation or retrieval failed'):
                        self.command.do_run(args, [])
                    self.assertEqual(run.call_count, 3 if fail_copy else 2)
                    self.assertEqual(run.call_args.args[0][3:6], ['rm', '-rf', '--'])
                    stop.assert_not_called()

    def test_report_output_errors_are_explicit_and_clean_up(self):
        with tempfile.TemporaryDirectory() as build_dir:
            args = self.parse('report', '-d', build_dir)
            cache = config.resolve_data_dir(args, build_dir)
            with (
                patch.object(containers, 'resolve_engine', return_value='podman'),
                patch.object(containers.Container, 'ensure_running'),
                patch.object(containers.Container, 'data_mount', return_value=cache),
                patch.object(self.command, 'die', side_effect=fail),
                patch.object(os, 'makedirs', side_effect=OSError('read-only output')),
                patch.object(subprocess, 'run') as run,
            ):
                run.return_value = subprocess.CompletedProcess([], 0, '', '')
                with self.assertRaisesRegex(RuntimeError, 'Could not write report output: read-only output'):
                    self.command.do_run(args, [])
                self.assertEqual(run.call_count, 2)
                self.assertEqual(run.call_args.args[0][3:6], ['rm', '-rf', '--'])

    def test_report_cleanup_failure_is_reported(self):
        with tempfile.TemporaryDirectory() as build_dir:
            args = self.parse('report', '-d', build_dir)
            cache = config.resolve_data_dir(args, build_dir)
            with (
                patch.object(containers, 'resolve_engine', return_value='podman'),
                patch.object(containers.Container, 'ensure_running'),
                patch.object(containers.Container, 'data_mount', return_value=cache),
                patch.object(self.command, 'wrn') as warning,
                patch.object(subprocess, 'run', side_effect=[
                    subprocess.CompletedProcess([], 0),
                    subprocess.CompletedProcess([], 0),
                    subprocess.CalledProcessError(1, 'rm', stderr='permission denied'),
                ]),
            ):
                self.command.do_run(args, [])
                warning.assert_called_once()
                self.assertIn('permission denied', warning.call_args.args[0])

    def test_export_formats_skip_import_and_copy_only_the_scoped_output(self):
        selected_id = '00000000-0000-0000-0000-000000000002'
        projects = [
            {'name': 'other', 'variants': [{'name': 'native', 'id': str(uuid.UUID(int=3))}]},
            {'name': 'zephyr', 'variants': [{'name': 'native', 'id': selected_id}]},
        ]
        for engine in ['podman', 'docker']:
            for output_format, filename in config.SBOM_EXPORT_FILES.items():
                with (
                    self.subTest(engine=engine, format=output_format),
                    tempfile.TemporaryDirectory() as build_dir,
                ):
                    args = self.parse(
                        'export', '-d', build_dir, '--container-engine', engine,
                        '--container-name', 'demo', '--project', 'zephyr', '--variant', 'native',
                        '--format', output_format, '--output-dir', build_dir,
                    )
                    cache = config.resolve_data_dir(args, build_dir)
                    temporary_dir = '/tmp/vulnscout_export_00000000000000000000000000000001'
                    with (
                        patch.object(containers, 'resolve_engine', return_value=engine),
                        patch.object(containers.Container, 'ensure_running') as ensure,
                        patch.object(containers.Container, 'data_mount', return_value=cache),
                        patch.object(self.command, '_run_west_spdx') as generate,
                        patch.object(self.command, '_resolve_spdx_files') as resolve,
                        patch.object(self.command, '_run_vulnscout') as scan,
                        patch.object(uuid, 'uuid4', return_value=uuid.UUID(int=1)),
                        patch.object(subprocess, 'run') as run,
                    ):
                        run.return_value = subprocess.CompletedProcess(
                            [], 0, json.dumps(projects), '',
                        )
                        self.command.do_run(args, [])
                    ensure.assert_called_once_with(cache, config.DEFAULT_VULNSCOUT_IMAGE, '0.0.0.0', '7275')
                    generate.assert_not_called()
                    resolve.assert_not_called()
                    scan.assert_not_called()
                    self.assertEqual(run.call_count, 4)
                    self.assertEqual(run.call_args_list[0].args[0], [
                        engine, 'exec', '-w', '/scan', 'demo',
                        'python', '-c', containers.PROCESSING_LOCK_PROGRAM, '', '30',
                        'flask', '--app', 'src.bin.webapp', 'list-projects', '--json',
                    ])
                    self.assertTrue(run.call_args_list[0].kwargs['capture_output'])
                    self.assertEqual(run.call_args_list[1].args[0], [
                        engine, 'exec', '-e', 'GENERATE_DOCUMENTS=', '-w', '/scan',
                        'demo', 'python', '-c', containers.PROCESSING_LOCK_PROGRAM, '', '3600',
                        'flask', '--app', 'src.bin.webapp',
                        'export', '--format', output_format, '--variant-id', selected_id,
                        '--output-dir', temporary_dir,
                    ])
                    self.assertEqual(run.call_args_list[2].args[0], [
                        engine, 'cp', f'demo:{temporary_dir}/{filename}',
                        str(pathlib.Path(build_dir) / filename),
                    ])
                    self.assertEqual(run.call_args_list[3].args[0], [
                        engine, 'exec', 'demo', 'rm', '-rf', '--', temporary_dir,
                    ])
                    self.assertTrue(all(call.kwargs['check'] for call in run.call_args_list[:3]))

    def test_export_defaults_to_spdx3_and_stops_after_success(self):
        with tempfile.TemporaryDirectory() as build_dir:
            args = self.parse('export', '-d', build_dir, '--stop-after-run')
            cache = config.resolve_data_dir(args, build_dir)
            with (
                patch.object(containers, 'resolve_engine', return_value='podman'),
                patch.object(containers.Container, 'ensure_running'),
                patch.object(containers.Container, 'data_mount', return_value=cache),
                patch.object(self.command, '_resolve_export_variant_id', return_value=str(uuid.UUID(int=1))),
                patch.object(self.command, '_stop_vulnscout_container') as stop,
                patch.object(subprocess, 'run') as run,
            ):
                run.return_value = subprocess.CompletedProcess([], 0, '', '')
                self.command.do_run(args, [])
            self.assertIn('spdx3', run.call_args_list[0].args[0])
            self.assertEqual(run.call_args_list[1].args[0][-1], str(
                pathlib.Path(build_dir) / 'vulnscout-exports/sbom_spdx_v3_0.spdx.json'
            ))
            stop.assert_called_once_with(args)

    def test_export_rejects_conflicting_options_and_report_formats(self):
        cases = [
            ['--stop'], ['--serve'], ['--perform-scan'], ['--refresh-vulnerability-data'],
            ['--no-generate'], ['--spdx-file', 'app.jsonld'], ['--spdx-version', '3.1'],
            ['--vulnscout-cmd', '/demo/vulnscout'], ['--template', 'summary.adoc'],
            ['--format', 'html'], ['--format', 'pdf'],
        ]
        with tempfile.TemporaryDirectory() as build_dir:
            for options in cases:
                with (
                    self.subTest(options=options),
                    patch.object(self.command, 'die', side_effect=fail),
                    patch.object(containers, 'resolve_engine') as engine,
                ):
                    with self.assertRaises(RuntimeError):
                        self.command.do_run(self.parse('export', '-d', build_dir, *options), [])
                    engine.assert_not_called()
            with patch.object(self.command, 'die', side_effect=fail):
                with self.assertRaisesRegex(RuntimeError, 'report --format'):
                    self.command.do_run(self.parse('report', '-d', build_dir, '--format', 'spdx2'), [])

    def test_export_rejects_missing_ambiguous_or_invalid_scope_without_exporting(self):
        variant = {'name': 'native', 'id': str(uuid.UUID(int=1))}
        cases = [
            'invalid-json', '{}', '[null]',
            '[]', '[{"name": "zephyr", "variants": []}]',
            '[{"name": "zephyr", "variants": null}]',
            '[{"name": "zephyr", "variants": [null]}]',
            '[{"name": "zephyr", "variants": [{"name": "native"}]}]',
            '[{"name": "zephyr", "variants": [{"name": "native", "id": "invalid"}]}]',
            json.dumps([{'name': 'zephyr', 'variants': [variant, variant]}]),
        ]
        with tempfile.TemporaryDirectory() as build_dir:
            args = self.parse('export', '-d', build_dir, '--project', 'zephyr', '--variant', 'native')
            cache = config.resolve_data_dir(args, build_dir)
            for output in cases:
                with (
                    self.subTest(output=output),
                    patch.object(containers, 'resolve_engine', return_value='podman'),
                    patch.object(containers.Container, 'ensure_running'),
                    patch.object(containers.Container, 'data_mount', return_value=cache),
                    patch.object(self.command, 'die', side_effect=fail),
                    patch.object(subprocess, 'run') as run,
                ):
                    run.return_value = subprocess.CompletedProcess([], 0, output, '')
                    with self.assertRaises(RuntimeError):
                        self.command.do_run(args, [])
                    run.assert_called_once()
                    self.assertIn('list-projects', run.call_args.args[0])

    def test_export_scope_query_failure_is_explicit(self):
        args = self.parse('export')
        with (
            patch.object(self.command, 'die', side_effect=fail),
            patch.object(subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'list-projects')),
        ):
            with self.assertRaisesRegex(RuntimeError, 'Could not resolve export scope'):
                self.command._resolve_export_variant_id(self.container(), args)

    def test_cache_is_checked_before_starting_or_reusing_container(self):
        for state in ['running', 'exited']:
            for mount in ['', '/another/cache']:
                with (
                    self.subTest(state=state, mount=mount),
                    patch.object(containers.Container, 'state', return_value=state),
                    patch.object(containers.Container, 'data_mount', return_value=mount),
                    patch.object(subprocess, 'run') as run,
                ):
                    with self.assertRaisesRegex(process.VulnScoutError, 'must mount the selected cache'):
                        self.container().ensure_running('/selected/cache', 'sfl:custom', '0.0.0.0', '7275')
                    run.assert_not_called()

    def test_symlink_equivalent_cache_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = pathlib.Path(directory) / 'cache'
            cache.mkdir()
            alias = pathlib.Path(directory) / 'alias'
            alias.symlink_to(cache, target_is_directory=True)
            containers.validate_cache_mount(str(alias), str(cache))
            with (
                patch.object(containers.Container, 'state', return_value='exited'),
                patch.object(containers.Container, 'data_mount', return_value=str(alias)),
                patch.object(containers.Container, 'wait_ready'),
                patch.object(subprocess, 'run') as run,
            ):
                self.container().ensure_running(str(cache), 'sfl:custom', '0.0.0.0', '7275')
                self.assertEqual(run.call_args.args[0], ['podman', 'start', 'demo'])

    def test_container_state_uses_one_query_and_exact_names(self):
        for output, expected in [
            ('vulnscout-other\trunning\nvulnscout\texited\n', 'exited'),
            ('vulnscout-other\trunning\n', None), ('', None),
        ]:
            with (
                self.subTest(output=output),
                patch.object(subprocess, 'run',
                             return_value=subprocess.CompletedProcess([], 0, output, '')) as run,
            ):
                self.assertEqual(self.container(name='vulnscout').state(), expected)
                run.assert_called_once()
                self.assertEqual(run.call_args.args[0], [
                    'podman', 'ps', '-a', '--format', '{{.Names}}\t{{.State}}',
                ])
        with patch.object(subprocess, 'run',
                          return_value=subprocess.CompletedProcess([], 0, 'unexpected', '')):
            with self.assertRaisesRegex(process.VulnScoutError, 'Invalid container status'):
                self.container(name='vulnscout').state()

    def test_private_workspace_is_unique_and_cleans_only_owned_paths(self):
        with patch.object(subprocess, 'run') as run:
            with self.container().input_workspace() as first:
                self.assertTrue(first.startswith('/tmp/west_vulnscout_'))
            with self.container().input_workspace() as second:
                self.assertNotEqual(first, second)
            self.assertEqual(run.call_count, 4)
            for call, directory in zip(run.call_args_list[1::2], [first, second]):
                self.assertEqual(call.args[0], ['podman', 'exec', 'demo', 'rm', '-rf', '--', directory])

    def test_processing_cleans_owned_workspace_for_all_native_exit_statuses(self):
        success = subprocess.CompletedProcess([], 0, '', '')
        for status, message in [(0, None), (2, None), (1, 'VulnScout failed'), (75, 'processing this cache')]:
            result = success if status == 0 else subprocess.CalledProcessError(status, 'entrypoint')
            with (
                self.subTest(status=status),
                patch.object(containers, 'resolve_engine', return_value='podman'),
                patch.object(containers.Container, 'ensure_running'),
                patch.object(containers.Container, 'check_processing_support', return_value=INTERFACE),
                patch.object(subprocess, 'run', side_effect=[success, success, result, success]) as run,
            ):
                args = self.parse('--match-condition', 'cvss >= 9')
                if message:
                    with self.assertRaisesRegex(process.VulnScoutError, message):
                        self.command._run_vulnscout(args, ['/host/app.jsonld'], '/cache')
                else:
                    self.assertEqual(self.command._run_vulnscout(args, ['/host/app.jsonld'], '/cache'), status)
                self.assertEqual(run.call_count, 4)
                directory = run.call_args_list[0].args[0][-1].removesuffix('/staged')
                self.assertEqual(run.call_args_list[1].args[0], [
                    'podman', 'cp', '/host/app.jsonld', f'vulnscout:{directory}/staged/1_app.spdx.json',
                ])
                command = run.call_args_list[2].args[0]
                self.assertIn(f'VULNSCOUT_INPUTS_DIR={directory}/inputs', command)
                self.assertEqual(command[7:13], [
                    'python', '-c', containers.PROCESSING_LOCK_PROGRAM,
                    containers.PROCESSING_LOCK, '3600', '/scan/src/entrypoint.sh',
                ])
                self.assertEqual(run.call_args.args[0][-4:], ['rm', '-rf', '--', directory])

    def test_partial_copy_failure_cleans_workspace_without_processing(self):
        success = subprocess.CompletedProcess([], 0, '', '')
        with (
            patch.object(containers, 'resolve_engine', return_value='podman'),
            patch.object(containers.Container, 'ensure_running'),
            patch.object(containers.Container, 'check_processing_support', return_value=INTERFACE),
            patch.object(subprocess, 'run', side_effect=[
                success, success, subprocess.CalledProcessError(1, 'cp'), success,
            ]) as run,
        ):
            with self.assertRaisesRegex(process.VulnScoutError, 'Staging SPDX file /host/build.jsonld'):
                self.command._run_vulnscout(self.parse(), ['/host/app.jsonld', '/host/build.jsonld'], '/cache')
            self.assertEqual(run.call_count, 4)
            self.assertEqual(run.call_args.args[0][3:6], ['rm', '-rf', '--'])
            self.assertFalse(any(containers.PROCESSING_LOCK_PROGRAM in call.args[0] for call in run.call_args_list))

    def test_cleanup_failure_does_not_mask_processing_failure(self):
        with (
            patch.object(self.command, 'wrn') as warning,
            patch.object(subprocess, 'run', side_effect=[
                subprocess.CompletedProcess([], 0, '', ''),
                subprocess.CalledProcessError(1, 'rm', stderr='permission denied'),
            ]),
        ):
            with self.assertRaisesRegex(process.VulnScoutError, 'primary processing failure'):
                with self.container().input_workspace():
                    raise process.VulnScoutError('primary processing failure')
            warning.assert_called_once()
            self.assertIn('permission denied', warning.call_args.args[0])

    @unittest.skipUnless(os.name == 'posix', 'container lock uses POSIX fcntl')
    def test_lock_survives_exec_and_releases_for_all_processing_statuses(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = pathlib.Path(directory) / 'ready'
            command = [
                sys.executable, '-c', containers.PROCESSING_LOCK_PROGRAM,
                str(pathlib.Path(directory) / 'lock'), '5', sys.executable, '-c',
            ]
            with subprocess.Popen([
                *command, 'import pathlib, sys; pathlib.Path(sys.argv[1]).touch(); sys.stdin.read(1)',
                str(marker),
            ], stdin=subprocess.PIPE, text=True) as owner:
                try:
                    deadline = time.monotonic() + 5
                    while not marker.exists() and time.monotonic() < deadline:
                        self.assertIsNone(owner.poll())
                        time.sleep(0.01)
                    self.assertTrue(marker.exists())
                    self.assertEqual(subprocess.run(
                        [*command, 'raise SystemExit(0)'], timeout=5,
                    ).returncode, containers.LOCK_BUSY)
                finally:
                    owner.communicate(input='x', timeout=5)
                self.assertEqual(owner.returncode, 0)
            for status in [2, 1, 0]:
                self.assertEqual(subprocess.run(
                    [*command, f'raise SystemExit({status})'], timeout=5,
                ).returncode, status)

    def test_incompatible_image_is_rejected_before_staging(self):
        self.interface_patch.stop()
        with (
            patch.object(containers, 'resolve_engine', return_value='podman'),
            patch.object(containers.Container, 'ensure_running'),
            patch.object(containers.Container, 'input_workspace') as workspace,
            patch.object(containers.Container, 'stage_files') as stage,
            patch.object(subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'probe')),
        ):
            with self.assertRaisesRegex(process.VulnScoutError, 'Reading VulnScout interface contract failed'):
                self.command._run_vulnscout(self.parse(), ['/host/app.jsonld'], '/cache')
            workspace.assert_not_called()
            stage.assert_not_called()

    def test_invalid_direct_options_are_rejected_before_generation(self):
        for options in [('--dev',), ('--serve', '--stop-after-run'), ('--match-condition', ' ')]:
            with (
                self.subTest(options=options),
                patch.object(self.command, 'die', side_effect=fail),
                patch.object(self.command, '_run_west_spdx') as generate,
                patch.object(subprocess, 'run') as run,
            ):
                with self.assertRaises(RuntimeError):
                    self.command.do_run(self.parse(*options), [])
                generate.assert_not_called()
                run.assert_not_called()

    def test_command_runner_reports_stderr_and_expected_policy_status(self):
        with patch.object(subprocess, 'run',
                          side_effect=subprocess.CalledProcessError(1, 'query', stderr='permission denied')):
            with self.assertRaisesRegex(process.VulnScoutError, 'Query failed with exit code 1: permission denied'):
                process.run_command(['engine', 'query'], 'Query', capture_output=True)
        with patch.object(subprocess, 'run', side_effect=FileNotFoundError('not installed')):
            with self.assertRaisesRegex(process.VulnScoutError, 'could not execute engine'):
                process.run_command(['engine', 'query'], 'Query')
        with patch.object(subprocess, 'run', side_effect=subprocess.CalledProcessError(2, 'policy')):
            self.assertEqual(process.run_command(['policy'], 'Policy', accepted_codes=(0, 2)).returncode, 2)
            with self.assertRaises(process.VulnScoutError):
                process.run_command(['policy'], 'Policy')

    def test_generation_retries_only_for_confirmed_missing_31_bindings(self):
        missing = "AttributeError: module 'spdx_python_model' has no attribute 'v3_1'\n"
        args = self.parse('--spdx-version', '3.1', '--include-sdk', '--analyze-includes', '--timeout', '20')
        with (
            patch.object(self.command, 'wrn') as warning,
            patch.object(subprocess, 'run', side_effect=[
                subprocess.CalledProcessError(1, 'west', stderr=missing),
                subprocess.CompletedProcess([], 0, '', ''),
            ]) as run,
        ):
            self.command._run_west_spdx(args, '/build', '/spdx')
            self.assertEqual(run.call_count, 2)
            self.assertEqual(run.call_args_list[0].args[0][-4:], ['--spdx-version', '3.1', '--include-sdk', '--analyze-includes'])
            self.assertEqual(run.call_args_list[1].args[0][-4:], ['--spdx-version', '3.0', '--include-sdk', '--analyze-includes'])
            self.assertEqual([call.kwargs['timeout'] for call in run.call_args_list], [20, 20])
            warning.assert_called_once()

    def test_generation_does_not_downgrade_unrelated_failures_or_timeouts(self):
        for failure in [
            subprocess.CalledProcessError(1, 'west', stderr='PermissionError: denied'),
            subprocess.CalledProcessError(1, 'west', stderr='Invalid CMake metadata'),
            subprocess.CalledProcessError(1, 'west', stderr="ModuleNotFoundError: No module named 'spdx_python_model'"),
            subprocess.CalledProcessError(1, 'west', stderr='unsupported SPDX version 3.1'),
            subprocess.CalledProcessError(1, 'west', stderr=(
                "AttributeError: module 'spdx_python_model' has no attribute 'v3_1'\n"
                "PermissionError: unrelated terminal failure"
            )),
            subprocess.TimeoutExpired('west', 1, stderr=b'old v3_1 error'),
            FileNotFoundError('west unavailable'),
        ]:
            with (
                self.subTest(failure=failure),
                patch.object(self.command, 'wrn') as warning,
                patch.object(subprocess, 'run', side_effect=failure) as run,
            ):
                with self.assertRaises(process.VulnScoutError):
                    self.command._run_west_spdx(self.parse('--spdx-version', '3.1'), '/build', '/spdx')
                run.assert_called_once()
                warning.assert_not_called()

    def test_generation_preserves_captured_31_output(self):
        with (
            patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'progress\n', 'experimental\n')),
            contextlib.redirect_stdout(io.StringIO()) as stdout,
            contextlib.redirect_stderr(io.StringIO()) as stderr,
        ):
            self.command._run_west_spdx(self.parse('--spdx-version', '3.1'), '/build', '/spdx')
            self.assertEqual(stdout.getvalue(), 'progress\n')
            self.assertEqual(stderr.getvalue(), 'experimental\n')

    def test_invalid_timeouts_are_rejected_before_execution(self):
        for value in ['0', '-1', 'nan', 'inf', 'not-a-number', '86401']:
            with self.subTest(value=value), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    self.parse('--timeout', value)

    def test_management_and_probe_timeouts_are_explicit(self):
        with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')) as run:
            self.container().state()
            self.assertEqual(run.call_args.kwargs['timeout'], 30)
            self.container().wait_ready()
            self.assertEqual(run.call_args.kwargs['timeout'], 5)
        with patch.object(subprocess, 'run', side_effect=subprocess.TimeoutExpired('exec', 5)) as run:
            with self.assertRaisesRegex(process.VulnScoutError, 'timed out after 5 seconds'):
                self.container().wait_ready()
            run.assert_called_once()

    def test_wrapper_deadline_and_interactive_exemption(self):
        for serve, expected in [(False, 12), (True, None)]:
            args = self.parse('--vulnscout-cmd', 'wrapper', '--timeout', '12', *(['--serve'] if serve else []))
            with self.subTest(serve=serve), patch.object(subprocess, 'run') as run:
                self.command._run_vulnscout(args, [], '/cache')
                self.assertEqual(run.call_args.kwargs['timeout'], expected)

    def test_timeout_diagnostics_decode_partial_output(self):
        with patch.object(subprocess, 'run', side_effect=subprocess.TimeoutExpired(
            ['query'], 2, output=b'partial output', stderr=b'engine stalled',
        )):
            with self.assertRaisesRegex(process.VulnScoutError, 'Query timed out after 2 seconds: engine stalled') as error:
                process.run_command(['query'], 'Query', capture_output=True, timeout=2)
            self.assertTrue(error.exception.timed_out)
            self.assertEqual(error.exception.stdout, 'partial output')
            self.assertEqual(error.exception.stderr, 'engine stalled')

    def test_readiness_uses_common_diagnostics(self):
        with (
            patch.object(time, 'sleep'),
            patch.object(subprocess, 'run',
                         side_effect=subprocess.CalledProcessError(125, 'exec', stderr='container exited')) as run,
        ):
            with self.assertRaisesRegex(process.VulnScoutError, 'Last error: .*container exited'):
                self.container().wait_ready(retries=2)
            self.assertEqual(run.call_count, 2)

    def test_command_builders_preserve_arguments_without_shell_parsing(self):
        args = self.parse('--namespace-prefix', 'https://example.org/my sbom',
                          '--include-sdk', '--analyze-includes')
        self.assertEqual(config.spdx_command(args, '/my build', '/my spdx', '3.1'), [
            'west', 'spdx', '--build-dir', '/my build', '--spdx-dir', '/my spdx',
            '--spdx-version', '3.1', '--namespace-prefix', 'https://example.org/my sbom',
            '--include-sdk', '--analyze-includes',
        ])
        self.assertEqual(containers.container_exec(
            'podman', 'demo', ['command', 'one argument'], environment={'KEY': 'a b'}, workdir='/my dir',
        ), ['podman', 'exec', '-e', 'KEY=a b', '-w', '/my dir', 'demo', 'command', 'one argument'])


class BackendInterfaceTests(unittest.TestCase):
    def container(self, **kwargs):
        return containers.Container(
            'podman', 'isolated', info=lambda message: None, warn=lambda message: None,
            debug=lambda message: None, **kwargs,
        )

    def test_contract_rejects_missing_unsupported_and_malformed_fields(self):
        invalid = ['', '<no value>', '{}', '[]', 'null']
        for updates in [
            {'version': 2}, {'version': True}, {'features': []}, {'features': ['isolated-inputs']},
            {'features': 'isolated-inputs'}, {'entrypoint': []}, {'cli': 'flask'},
            {'python': ['']}, {'python': [None]}, {'workdir': 'relative'},
            {'workdir': '/opt/../scan'}, {'workdir': None},
        ]:
            invalid.append(json.dumps({**INTERFACE_DATA, **updates}))
        for payload in invalid:
            with self.subTest(payload=payload), self.assertRaisesRegex(process.VulnScoutError, 'Rebuild or upgrade'):
                backend.parse_interface(payload)

    def test_contract_is_read_once_from_metadata_without_source_probing(self):
        instance = self.container()
        with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess(
            [], 0, json.dumps({backend.INTERFACE_LABEL: json.dumps(INTERFACE_DATA)}), '',
        )) as run:
            self.assertEqual(instance.check_processing_support(), INTERFACE)
            self.assertIs(instance.check_processing_support(), instance.check_processing_support())
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0], [
                'podman', 'inspect', '--format',
                '{{json .Config.Labels}}', 'isolated',
            ])
            self.assertEqual(run.call_args.kwargs['timeout'], 30)

    def test_unlabeled_v023_uses_explicit_version_adapter(self):
        self.assertEqual(
            backend.resolve_interface(json.dumps({backend.VERSION_LABEL: 'v0.23'})),
            backend.BackendInterface(
                entrypoint=('/scan/src/entrypoint.sh',),
                cli=('flask', '--app', 'src.bin.webapp'),
                python=('python3',), workdir='/scan',
            ),
        )

    def test_unknown_or_invalid_metadata_is_not_guessed_from_tags(self):
        payloads = ['', 'null', '[]', '{}', 'not JSON']
        payloads.extend(json.dumps({backend.VERSION_LABEL: version}) for version in (
            'v0.22', 'v0.24', 'latest', '0.23', '', None, ['v0.23'],
        ))
        for payload in payloads:
            with self.subTest(payload=payload), self.assertRaisesRegex(
                process.VulnScoutError, 'Image tags alone',
            ):
                backend.resolve_interface(payload)

    def test_invalid_declaration_never_falls_back_to_v023_adapter(self):
        for declaration in ('', '{}', 'null', 'invalid JSON', None, False, INTERFACE_DATA,
                            json.dumps({**INTERFACE_DATA, 'version': 2}),
                            json.dumps({**INTERFACE_DATA, 'features': []})):
            with self.subTest(declaration=declaration), self.assertRaises(process.VulnScoutError):
                backend.resolve_interface(json.dumps({
                    backend.VERSION_LABEL: 'v0.23', backend.INTERFACE_LABEL: declaration,
                }))

    def test_valid_declaration_takes_precedence_over_version_adapter(self):
        declaration = {**INTERFACE_DATA, 'workdir': '/opt/service'}
        for version in ('v0.23', 'v0.24', None):
            with self.subTest(version=version):
                self.assertEqual(backend.resolve_interface(json.dumps({
                    backend.VERSION_LABEL: version,
                    backend.INTERFACE_LABEL: json.dumps(declaration),
                })), backend.parse_interface(json.dumps(declaration)))

    def test_v023_adapter_is_selected_before_starting_stopped_container(self):
        instance = self.container()
        success = subprocess.CompletedProcess([], 0, '', '')
        metadata = subprocess.CompletedProcess(
            [], 0, json.dumps({backend.VERSION_LABEL: 'v0.23'}), '',
        )
        with (
            patch.object(instance, 'state', return_value='exited'),
            patch.object(instance, 'data_mount', return_value='/host/cache'),
            patch.object(instance, 'wait_ready') as ready,
            patch.object(instance, 'info') as info,
            patch.object(subprocess, 'run', side_effect=[metadata, success]) as run,
        ):
            instance.ensure_running('/host/cache', 'ignored:image', '0.0.0.0', '7275')
            self.assertEqual(run.call_args_list[0].args[0], [
                'podman', 'inspect', '--format', '{{json .Config.Labels}}', 'isolated',
            ])
            self.assertEqual(run.call_args_list[1].args[0], ['podman', 'start', 'isolated'])
            self.assertIs(instance.check_processing_support(), backend.V023_INTERFACE)
            self.assertEqual(run.call_count, 2)
            info.assert_any_call('Using the built-in VulnScout v0.23 compatibility adapter')
            ready.assert_called_once()

    def test_discovered_commands_and_workdir_are_used_without_scan_paths(self):
        interface = backend.parse_interface(json.dumps({
            **INTERFACE_DATA, 'entrypoint': ['/opt/service/start'],
            'cli': ['/opt/service/bin/cli', '--app', 'app'],
            'python': ['/opt/service/bin/python3'], 'workdir': '/opt/service',
        }))
        instance = self.container(timeout=7)
        with (
            patch.object(instance, 'check_processing_support', return_value=interface),
            patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')) as run,
        ):
            instance.run_processing(['--project', 'one'], '/tmp/owned')
            command = run.call_args.args[0]
            self.assertEqual(command[:9], [
                'podman', 'exec', '-e', 'VULNSCOUT_INPUTS_DIR=/tmp/owned/inputs',
                '-w', '/opt/service', 'isolated', '/opt/service/bin/python3', '-c',
            ])
            self.assertEqual(command[-4:], ['7', '/opt/service/start', '--project', 'one'])
            self.assertEqual(run.call_args.kwargs['timeout'], 42)
            instance.run_backend([*interface.cli, 'report', 'summary.adoc'])
            self.assertEqual(run.call_args.args[0][-5:], [
                '/opt/service/bin/cli', '--app', 'app', 'report', 'summary.adoc',
            ])

    def test_backend_timeout_does_not_masquerade_as_policy_or_lock_contention(self):
        instance = self.container(timeout=1)
        with (
            patch.object(instance, 'check_processing_support', return_value=INTERFACE),
            patch.object(subprocess, 'run', side_effect=subprocess.CalledProcessError(124, 'backend')),
        ):
            with self.assertRaisesRegex(process.VulnScoutError, 'timed out after 1 seconds') as error:
                instance.run_processing([], '/tmp/owned', accepted_codes=(0, 2))
            self.assertTrue(error.exception.timed_out)

    @unittest.skipUnless(os.name == 'posix', 'container deadline uses POSIX process groups')
    def test_inner_deadline_stops_descendants_before_releasing_the_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = pathlib.Path(directory) / 'descendant'
            pidfile = pathlib.Path(directory) / 'pid'
            grandchild = (
                "import os, pathlib, signal, sys, time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "pathlib.Path(sys.argv[2]).write_text(str(os.getpid()) + ' ' + str(os.getpgrp())); "
                "p = pathlib.Path(sys.argv[1]); p.write_text('ready'); "
                "time.sleep(1); p.write_text('escaped'); time.sleep(10)"
            )
            child = (
                "import subprocess, sys, time; "
                f"subprocess.Popen([sys.executable, '-c', {grandchild!r}, sys.argv[1], sys.argv[2]]); "
                "time.sleep(10)"
            )
            prefix = [
                sys.executable, '-c', containers.PROCESSING_LOCK_PROGRAM,
                str(pathlib.Path(directory) / 'lock'),
            ]
            try:
                result = subprocess.run(
                    [*prefix, '0.5', sys.executable, '-c', child, str(marker), str(pidfile)],
                    capture_output=True, text=True, timeout=8,
                )
                self.assertEqual(result.returncode, 124, result.stderr)
                self.assertEqual(marker.read_text(), 'ready')
                time.sleep(1.1)
                self.assertEqual(marker.read_text(), 'ready')
                released = subprocess.run(
                    [*prefix, '1', sys.executable, '-c', 'raise SystemExit(0)'],
                    capture_output=True, text=True, timeout=3,
                )
                self.assertEqual(released.returncode, 0, released.stderr)
            finally:
                if pidfile.exists():
                    try:
                        pid, group = map(int, pidfile.read_text().split())
                        if os.getpgid(pid) == group:
                            os.kill(pid, 9)
                    except ProcessLookupError:
                        pass


if __name__ == '__main__':
    unittest.main()
