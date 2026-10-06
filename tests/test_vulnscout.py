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


class StopCommandTests(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
