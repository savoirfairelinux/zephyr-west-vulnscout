# Copyright (c) 2026
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
import os
import pathlib
import shlex
import shutil
import textwrap
import time
import uuid

from .process import VulnScoutError, run_command


PROCESSING_LOCK = '/cache/vulnscout/.west-vulnscout.lock'
LOCK_BUSY = 75
PROCESSING_LOCK_PROGRAM = textwrap.dedent(f"""\
    import fcntl
    import os
    import sys

    descriptor = os.open(sys.argv[1], os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit({LOCK_BUSY})
    # Keep the lock through exec until the processing command exits.
    os.set_inheritable(descriptor, True)
    os.execv(sys.argv[2], sys.argv[2:])
""")


def resolve_engine(preferred: str) -> str:
    if preferred in ('docker', 'podman'):
        if shutil.which(preferred):
            return preferred
        raise VulnScoutError(f'Requested container engine is not available: {preferred}')
    for candidate in ('podman', 'docker'):
        if shutil.which(candidate):
            return candidate
    raise VulnScoutError('Could not find podman or docker in PATH')


def container_exec(
    engine: str, name: str, command: Sequence[str], *,
    environment: Mapping[str, str] | None = None, workdir: str | None = None,
) -> list[str]:
    result = [engine, 'exec']
    for key, value in (environment or {}).items():
        result.extend(['-e', f'{key}={value}'])
    if workdir is not None:
        result.extend(['-w', workdir])
    return result + [name, *command]


def validate_cache_mount(mounted_dir: str, data_dir: str) -> None:
    if not mounted_dir or os.path.realpath(mounted_dir) != os.path.realpath(data_dir):
        raise VulnScoutError(
            'Container must mount the selected cache at /cache/vulnscout. '
            f'Requested: {data_dir}; mounted: {mounted_dir or "(none)"}. '
            'Select the matching --container-name or --vulnscout-data-dir.'
        )


class Container:
    def __init__(
        self, engine: str, name: str, *, info: Callable[[str], None],
        warn: Callable[[str], None], debug: Callable[[str], None],
    ) -> None:
        self.engine, self.name = engine, name
        self.info, self.warn, self.debug = info, warn, debug

    def state(self) -> str | None:
        output = run_command(
            [self.engine, 'ps', '-a', '--format', '{{.Names}}\t{{.State}}'],
            f'Querying containers with {self.engine}', capture_output=True,
        )
        for line in output.stdout.splitlines():
            name, separator, state = line.partition('\t')
            if not separator:
                raise VulnScoutError(f'Invalid container status returned by {self.engine}: {line}')
            if name == self.name:
                return state
        return None

    def data_mount(self) -> str:
        output = run_command([
            self.engine, 'inspect', '--format',
            '{{range .Mounts}}{{if eq .Destination "/cache/vulnscout"}}{{.Source}}{{end}}{{end}}',
            self.name,
        ], f'Inspecting container "{self.name}"', capture_output=True)
        return output.stdout.strip()

    def wait_ready(self, retries: int = 10) -> None:
        last_error = None
        for _ in range(retries):
            try:
                run_command(
                    container_exec(self.engine, self.name, ['true']),
                    f'Probing container "{self.name}"', capture_output=True,
                )
                return
            except VulnScoutError as error:
                if error.returncode is None:
                    raise
                last_error = error
            time.sleep(1)
        raise VulnScoutError(
            f'Container "{self.name}" did not become ready. '
            f'Check logs with: {self.engine} logs {self.name}. Last error: {last_error}'
        )

    def ensure_running(self, data_dir: str, image: str, host: str, port: str) -> None:
        state = self.state()
        if state is not None:
            validate_cache_mount(self.data_mount(), data_dir)
            if state != 'running':
                command = [self.engine, 'start', self.name]
                self.info(f'Starting existing VulnScout container: {shlex.join(command)}')
                run_command(command, f'Starting container "{self.name}"')
                self.wait_ready()
            return
        os.makedirs(data_dir, exist_ok=True)
        command = [
            self.engine, 'run', '-d', '--name', self.name,
            '-p', f'{port}:{port}', '-e', f'FLASK_RUN_HOST={host}', '-e', f'FLASK_RUN_PORT={port}',
            '-v', f'{data_dir}:/cache/vulnscout', image, 'daemon',
        ]
        self.info(f'Starting VulnScout container: {shlex.join(command)}')
        run_command(command, f'Starting VulnScout container from image {image}')
        self.wait_ready()
        validate_cache_mount(self.data_mount(), data_dir)

    def stop(self, best_effort: bool = False) -> None:
        command = [self.engine, 'rm', '-f', self.name]
        self.info(f'Stopping VulnScout container: {shlex.join(command)}')
        try:
            run_command(
                command, f'Stopping container "{self.name}"', capture_output=True,
            )
        except VulnScoutError as error:
            if 'No such container' in str(error):
                self.warn(f'Container "{self.name}" is not running')
            elif best_effort:
                self.warn(str(error))
            else:
                raise

    @contextmanager
    def input_workspace(self) -> Iterator[str]:
        directory = f'/tmp/west_vulnscout_{uuid.uuid4().hex}'
        try:
            run_command(
                container_exec(self.engine, self.name, ['mkdir', '-p', f'{directory}/staged']),
                'Creating isolated input workspace',
            )
            yield directory
        finally:
            self.cleanup_directory(directory)

    def cleanup_directory(self, directory: str) -> None:
        try:
            run_command(
                container_exec(self.engine, self.name, ['rm', '-rf', '--', directory]),
                f'Removing temporary directory {directory}', capture_output=True,
            )
        except VulnScoutError as error:
            self.warn(str(error))

    def stage_files(self, spdx_files: Sequence[str], directory: str) -> list[str]:
        staged = []
        for idx, spdx_file in enumerate(spdx_files, start=1):
            source = pathlib.Path(spdx_file)
            basename = f'{source.stem}.spdx.json' if source.suffix.lower() == '.jsonld' else source.name
            staged_path = f'{directory}/staged/{idx}_{basename}'
            command = [self.engine, 'cp', spdx_file, f'{self.name}:{staged_path}']
            self.debug(f'Staging SPDX file into container: {shlex.join(command)}')
            run_command(command, f'Staging SPDX file {spdx_file}')
            staged.append(staged_path)
        return staged

    def check_processing_support(self) -> None:
        run_command(
            container_exec(self.engine, self.name, [
                'sh', '-c',
                "python -c 'import fcntl' && grep -q 'VULNSCOUT_INPUTS_DIR' /scan/src/entrypoint.sh",
            ]),
            'Checking isolated-input support (requires Python fcntl and VULNSCOUT_INPUTS_DIR)',
            capture_output=True,
        )

    def run_processing(
        self, arguments: Sequence[str], directory: str, *, accepted_codes: Sequence[int] = (0,),
    ) -> int:
        command = container_exec(
            self.engine, self.name,
            ['python', '-c', PROCESSING_LOCK_PROGRAM, PROCESSING_LOCK,
             '/scan/src/entrypoint.sh', *arguments],
            environment={'VULNSCOUT_INPUTS_DIR': f'{directory}/inputs'},
        )
        self.debug(f'Running VulnScout command: {shlex.join(command)}')
        try:
            return run_command(command, 'VulnScout', accepted_codes=accepted_codes).returncode
        except VulnScoutError as error:
            if error.returncode == LOCK_BUSY:
                raise VulnScoutError(
                    'Another west vulnscout operation is processing this cache. '
                    'Retry after it finishes.'
                ) from error
            raise
