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


def fail(message):
    raise RuntimeError(message)


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
                    cache = self.command._resolve_vulnscout_data_dir(args, build_dir)
                    report_dir = '/tmp/vulnscout_report_00000000000000000000000000000001'
                    filename = 'all_assessments.adoc' + (f'.{output_format}' if output_format else '')
                    output_dir = build_dir if output_format else str(pathlib.Path(build_dir) / 'vulnscout-reports')
                    with (
                        patch.object(self.command, '_resolve_container_engine', return_value=engine),
                        patch.object(self.command, '_ensure_container_running') as ensure,
                        patch.object(self.command, '_get_container_data_mount', return_value=cache),
                        patch.object(self.command, '_run_west_spdx') as generate,
                        patch.object(self.command, '_resolve_spdx_files') as resolve,
                        patch.object(self.command, '_run_vulnscout') as scan,
                        patch.object(vulnscout.uuid, 'uuid4', return_value=vulnscout.uuid.UUID(int=1)),
                        patch.object(vulnscout.subprocess, 'run') as run,
                    ):
                        run.return_value = subprocess.CompletedProcess([], 0, '', '')
                        self.command.do_run(args, [])
                    ensure.assert_called_once_with(engine, 'demo', args, cache)
                    generate.assert_not_called()
                    resolve.assert_not_called()
                    scan.assert_not_called()
                    expected = [
                        engine, 'exec', '-e', 'GENERATE_DOCUMENTS=', '-w', '/scan',
                        'demo', 'flask', '--app', 'src.bin.webapp',
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
            cache = self.command._resolve_vulnscout_data_dir(args, build_dir)
            with (
                patch.object(self.command, '_resolve_container_engine', return_value='podman'),
                patch.object(self.command, '_ensure_container_running'),
                patch.object(self.command, '_get_container_data_mount', return_value=cache),
                patch.object(self.command, '_stop_vulnscout_container') as stop,
                patch.object(vulnscout.subprocess, 'run') as run,
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
                    patch.object(self.command, '_resolve_container_engine') as engine,
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
                    patch.object(self.command, '_resolve_container_engine', return_value='podman'),
                    patch.object(self.command, '_ensure_container_running'),
                    patch.object(self.command, '_get_container_data_mount', return_value=mounted_dir),
                    patch.object(self.command, 'die', side_effect=fail),
                    patch.object(vulnscout.subprocess, 'run') as run,
                ):
                    with self.assertRaisesRegex(RuntimeError, 'must mount the selected cache'):
                        self.command.do_run(self.parse('report', '-d', build_dir), [])
                    run.assert_not_called()

    def test_report_failures_are_explicit_and_always_clean_up(self):
        with tempfile.TemporaryDirectory() as build_dir:
            for fail_copy in [False, True]:
                args = self.parse('report', '-d', build_dir, '--stop-after-run')
                cache = self.command._resolve_vulnscout_data_dir(args, build_dir)
                success = subprocess.CompletedProcess([], 0, '', '')
                results = ([success] if fail_copy else []) + [
                    subprocess.CalledProcessError(1, 'report'), success,
                ]
                with (
                    self.subTest(fail_copy=fail_copy),
                    patch.object(self.command, '_resolve_container_engine', return_value='podman'),
                    patch.object(self.command, '_ensure_container_running'),
                    patch.object(self.command, '_get_container_data_mount', return_value=cache),
                    patch.object(self.command, '_stop_vulnscout_container') as stop,
                    patch.object(self.command, 'die', side_effect=fail),
                    patch.object(vulnscout.subprocess, 'run', side_effect=results) as run,
                ):
                    with self.assertRaisesRegex(RuntimeError, 'generation or retrieval failed'):
                        self.command.do_run(args, [])
                    self.assertEqual(run.call_count, 3 if fail_copy else 2)
                    self.assertEqual(run.call_args.args[0][3:6], ['rm', '-rf', '--'])
                    stop.assert_not_called()

    def test_report_output_errors_are_explicit_and_clean_up(self):
        with tempfile.TemporaryDirectory() as build_dir:
            args = self.parse('report', '-d', build_dir)
            cache = self.command._resolve_vulnscout_data_dir(args, build_dir)
            with (
                patch.object(self.command, '_resolve_container_engine', return_value='podman'),
                patch.object(self.command, '_ensure_container_running'),
                patch.object(self.command, '_get_container_data_mount', return_value=cache),
                patch.object(self.command, 'die', side_effect=fail),
                patch.object(vulnscout.os, 'makedirs', side_effect=OSError('read-only output')),
                patch.object(vulnscout.subprocess, 'run') as run,
            ):
                run.return_value = subprocess.CompletedProcess([], 0, '', '')
                with self.assertRaisesRegex(RuntimeError, 'Could not write report output: read-only output'):
                    self.command.do_run(args, [])
                self.assertEqual(run.call_count, 2)
                self.assertEqual(run.call_args.args[0][3:6], ['rm', '-rf', '--'])

    def test_report_cleanup_failure_is_reported(self):
        with tempfile.TemporaryDirectory() as build_dir:
            args = self.parse('report', '-d', build_dir)
            cache = self.command._resolve_vulnscout_data_dir(args, build_dir)
            with (
                patch.object(self.command, '_resolve_container_engine', return_value='podman'),
                patch.object(self.command, '_ensure_container_running'),
                patch.object(self.command, '_get_container_data_mount', return_value=cache),
                patch.object(self.command, 'wrn') as warning,
                patch.object(vulnscout.subprocess, 'run', side_effect=[
                    subprocess.CompletedProcess([], 0),
                    subprocess.CompletedProcess([], 0),
                    subprocess.CompletedProcess([], 1, '', 'permission denied'),
                ]),
            ):
                self.command.do_run(args, [])
                warning.assert_called_once()
                self.assertIn('permission denied', warning.call_args.args[0])


if __name__ == '__main__':
    unittest.main()
