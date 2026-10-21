# Copyright (c) 2026
#
# SPDX-License-Identifier: Apache-2.0

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

from test_vulnscout import COMMAND_PATH, containers, process


WORKER = """
import argparse
import sys
from west.commands import _ExtFactory

command = _ExtFactory(sys.argv[1], 'vulnscout', 'ZephyrVulnScout')()
command.inf = print
command.wrn = print
command.dbg = lambda *args, **kwargs: None
command.die = sys.exit
parser = argparse.ArgumentParser()
command.do_add_parser(parser.add_subparsers())
command.do_run(parser.parse_args(['vulnscout', *sys.argv[2:]]), [])
"""


@unittest.skipUnless(os.environ.get('VULNSCOUT_INTEGRATION_IMAGE'), 'opt-in container smoke test')
class VulnScoutIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.engine = os.environ.get('VULNSCOUT_INTEGRATION_ENGINE', 'podman')
        self.assertIsNotNone(shutil.which(self.engine), f'{self.engine} is not installed')
        fixture_dir = pathlib.Path(os.environ['VULNSCOUT_INTEGRATION_SPDX_DIR']).resolve()
        self.fixtures = sorted(fixture_dir.glob('*.jsonld'))
        self.assertTrue(self.fixtures, f'No JSON-LD fixtures in {fixture_dir}')
        self.name = f'vulnscout-isolation-check-{uuid.uuid4().hex}'
        temporary = tempfile.TemporaryDirectory(prefix='west-vulnscout-check-')
        self.addCleanup(temporary.cleanup)
        self.directory = pathlib.Path(temporary.name)
        self.cache = self.directory / 'cache'
        self.cache.mkdir()
        self.build = self.directory / 'build'
        self.build.mkdir()
        self.container([
            'run', '-d', '--name', self.name, '--network', 'none',
            '-v', f'{self.cache}:/cache/vulnscout', '--entrypoint', '/bin/sleep',
            os.environ['VULNSCOUT_INTEGRATION_IMAGE'], 'infinity',
        ])
        self.addCleanup(self.remove_container)
        self.container(['exec', self.name, 'true'])

    def container(self, arguments):
        return subprocess.run(
            [self.engine, *arguments], check=True, capture_output=True, text=True, timeout=120,
        )

    def remove_container(self):
        if self.name is not None:
            self.container(['rm', '-f', self.name])
            self.name = None

    def command(self, variant, *options):
        arguments = [
            sys.executable, '-c', WORKER, str(COMMAND_PATH), '-d', str(self.build),
            '--no-generate', '--container-engine', self.engine, '--container-name', self.name,
            '--vulnscout-data-dir', str(self.cache), '--project', 'isolation-check', '--variant', variant,
        ]
        for fixture in self.fixtures:
            arguments.extend(['--spdx-file', str(fixture)])
        return [*arguments, *options]

    def run_west(self, variant, *options, expected=0):
        result = subprocess.run(
            self.command(variant, *options), capture_output=True, text=True, timeout=180,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def assert_no_workspaces(self):
        result = self.container([
            'exec', self.name, 'find', '/tmp', '-maxdepth', '1',
            '-type', 'd', '-name', 'west_vulnscout_*',
        ])
        self.assertEqual(result.stdout.strip(), '')

    def test_cache_lock_private_inputs_and_imports_with_attached_ui(self):
        instance = containers.Container(
            self.engine, self.name, info=lambda message: None,
            warn=lambda message: None, debug=lambda message: None,
        )
        interface = instance.check_processing_support()
        with self.assertRaisesRegex(process.VulnScoutError, 'processing timed out') as deadline:
            instance.run_backend([
                *interface.python, '-c',
                "import time; time.sleep(60)",
            ], lock=True, timeout=0.2, capture_output=True)
        self.assertTrue(deadline.exception.timed_out)
        self.assertIn('deadline exceeded', deadline.exception.stderr)
        pending_path = f'{interface.workdir}/inputs/spdx/pending.spdx.json'
        self.container([
            'exec', self.name, *interface.python, '-c',
            f"from pathlib import Path; p = Path({pending_path!r}); "
            "p.parent.mkdir(parents=True, exist_ok=True); p.write_text('untouched')",
        ])
        with (self.directory / 'lock.log').open('w') as log:
            lock = subprocess.Popen([
                self.engine, 'exec', self.name, *interface.python, '-c',
                "import fcntl, pathlib, time\n"
                f"lock = open({containers.PROCESSING_LOCK!r}, 'a')\n"
                "fcntl.flock(lock, fcntl.LOCK_EX)\n"
                "pathlib.Path('/tmp/west-lock-ready').touch()\n"
                "while not pathlib.Path('/tmp/west-lock-release').exists(): time.sleep(0.1)\n",
            ], stdout=log, stderr=subprocess.STDOUT)
            try:
                for _ in range(50):
                    ready = subprocess.run(
                        [self.engine, 'exec', self.name, 'test', '-f', '/tmp/west-lock-ready'],
                        capture_output=True, timeout=10,
                    )
                    if ready.returncode == 0:
                        break
                    self.assertIsNone(lock.poll(), (self.directory / 'lock.log').read_text())
                    time.sleep(0.1)
                else:
                    self.fail('Cache lock holder did not become ready')
                result = self.run_west('first', expected=1)
                self.assertIn('processing this cache', result.stderr)
                self.assertFalse((self.cache / 'vulnscout.db').exists())
                self.assert_no_workspaces()
            finally:
                self.container(['exec', self.name, 'touch', '/tmp/west-lock-release'])
                lock.wait(timeout=15)

        self.run_west('first')
        self.assert_no_workspaces()
        other_cache = self.directory / 'other-cache'
        result = self.run_west('wrong-cache', '--vulnscout-data-dir', str(other_cache), expected=1)
        self.assertIn('must mount the selected cache', result.stderr)
        self.assertFalse(other_cache.exists())

        with (self.directory / 'serve.log').open('w') as log:
            server = subprocess.Popen(self.command('first', '--serve'), stdout=log, stderr=subprocess.STDOUT)
            try:
                for _ in range(120):
                    self.assertIsNone(server.poll(), (self.directory / 'serve.log').read_text())
                    response = subprocess.run([
                        self.engine, 'exec', self.name, *interface.python, '-c',
                        "from urllib.request import urlopen; "
                        "assert urlopen('http://127.0.0.1:7275/', timeout=1).status == 200",
                    ], capture_output=True, timeout=10)
                    if response.returncode == 0:
                        break
                    time.sleep(0.5)
                else:
                    self.fail((self.directory / 'serve.log').read_text())
                self.assert_no_workspaces()
                self.run_west('second')
                self.run_west('first', '--refresh-vulnerability-data', '--match-condition', 'cvss >= 9.0')
                self.assertIsNone(server.poll())
                self.assert_no_workspaces()
                projects = json.loads(self.container([
                    'exec', '-w', interface.workdir, self.name,
                    *interface.cli, 'list-projects', '--json',
                ]).stdout)
                project = next(project for project in projects if project['name'] == 'isolation-check')
                self.assertEqual({variant['name'] for variant in project['variants']}, {'first', 'second'})
                pending = self.container(['exec', self.name, 'cat', pending_path])
                self.assertEqual(pending.stdout, 'untouched')
            finally:
                self.remove_container()
                server.wait(timeout=15)
