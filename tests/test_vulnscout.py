# Copyright (c) 2026
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import contextlib
import importlib.util
import io
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch


COMMAND_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / 'scripts' / 'west_commands' / 'vulnscout.py'
)
SPEC = importlib.util.spec_from_file_location('vulnscout', COMMAND_PATH)
vulnscout = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vulnscout)


class VulnScoutCommandTests(unittest.TestCase):
    def setUp(self):
        self.command = vulnscout.ZephyrVulnScout()
        info = patch.object(self.command, 'inf')
        info.start()
        self.addCleanup(info.stop)
        self.parser = argparse.ArgumentParser()
        self.command.do_add_parser(self.parser.add_subparsers())

    def parse(self, *arguments):
        return self.parser.parse_args(['vulnscout', *arguments])

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
                    patch.object(vulnscout.shutil, 'which', return_value='/usr/bin/podman'),
                    patch.object(vulnscout.subprocess, 'run') as run,
                ):
                    run.return_value = subprocess.CompletedProcess([], 0, '', '')
                    self.command.do_run(args, [])
                run.assert_called_once_with(
                    ['podman', 'rm', '-f', 'demo'], capture_output=True, text=True
                )

    def test_stop_honors_wrapper(self):
        args = self.parse('stop', '--vulnscout-cmd', '/demo/vulnscout')
        with patch.object(vulnscout.subprocess, 'run') as run:
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
                            patch.object(self.command, '_resolve_container_engine',
                                         return_value='podman'),
                            patch.object(self.command, '_ensure_container_running'),
                            patch.object(self.command, '_cleanup_staged_inputs'),
                            patch.object(self.command, '_stage_spdx_files',
                                         return_value=['/tmp/app.spdx.json']),
                            patch.object(vulnscout.subprocess, 'run') as run,
                        ):
                            self.command._run_vulnscout(args, ['/demo/app.jsonld'], '/cache')
                        if wrapper:
                            expected = ['/demo/vulnscout']
                            spdx_file = '/demo/app.jsonld'
                        else:
                            expected = ['podman', 'exec']
                            if serve:
                                expected.extend([
                                    '-e', 'FLASK_RUN_HOST=0.0.0.0',
                                    '-e', 'FLASK_RUN_PORT=7275',
                                ])
                            expected.extend(['vulnscout', '/scan/src/entrypoint.sh'])
                            spdx_file = '/tmp/app.spdx.json'
                        expected.extend([
                            '--project', 'demo', '--variant', 'native',
                            '--add-spdx', spdx_file,
                        ])
                        if perform_scan:
                            expected.extend(['--perform-scans', 'all'])
                        if serve:
                            expected.append('--serve')
                        run.assert_called_once()
                        self.assertEqual(run.call_args.args[0], expected)
                        self.assertTrue(run.call_args.kwargs['check'])

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
                args, files, self.command._resolve_vulnscout_data_dir(args, build_dir)
            )

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
                        patch.object(self.command, '_resolve_container_engine',
                                     return_value='podman'),
                        patch.object(self.command, '_ensure_container_running'),
                        patch.object(self.command, '_cleanup_staged_inputs') as cleanup,
                        patch.object(self.command, '_stage_spdx_files') as stage,
                        patch.object(vulnscout.subprocess, 'run') as run,
                    ):
                        self.command.do_run(args, [])
                    generate.assert_not_called()
                    resolve.assert_not_called()
                    cleanup.assert_not_called()
                    stage.assert_not_called()
                    expected = ['/demo/vulnscout'] if wrapper else ['podman', 'exec']
                    if not wrapper:
                        if serve:
                            expected.extend([
                                '-e', 'FLASK_RUN_HOST=0.0.0.0',
                                '-e', 'FLASK_RUN_PORT=7275',
                            ])
                        expected.extend(['vulnscout', '/scan/src/entrypoint.sh'])
                    expected.extend([
                        '--project', 'demo', '--variant', 'native',
                        '--refresh-vulnerability-data',
                    ])
                    if serve:
                        expected.append('--serve')
                    run.assert_called_once()
                    self.assertEqual(run.call_args.args[0], expected)

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
                patch.object(vulnscout.subprocess, 'run') as run,
            ):
                self.command.do_run(args, [])
            generate.assert_called_once()
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0], [
                '/demo/vulnscout', '--project', 'default', '--variant', 'default',
                '--add-spdx', files[0], '--perform-scans', 'all',
                '--refresh-vulnerability-data',
            ])


if __name__ == '__main__':
    unittest.main()
