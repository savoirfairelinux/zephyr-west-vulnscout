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
import subprocess
import textwrap
import time
import uuid

from .backend import CACHE_DIR, V023_INTERFACE, BackendInterface, resolve_interface
from .process import DEFAULT_OPERATION_TIMEOUT, MANAGEMENT_TIMEOUT, VulnScoutError, run_command


PROCESSING_LOCK = f'{CACHE_DIR}/.west-vulnscout.lock'
LOCK_BUSY = 75
PROCESSING_TIMED_OUT = 124
TIMEOUT_GRACE = 5
PROCESSING_LOCK_PROGRAM = textwrap.dedent(f"""\
    import fcntl
    import os
    import signal
    import subprocess
    import sys

    if sys.argv[1]:
        descriptor = os.open(sys.argv[1], os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            sys.exit({LOCK_BUSY})
    child = subprocess.Popen(sys.argv[3:], start_new_session=True)
    try:
        result = child.wait(timeout=float(sys.argv[2]))
    except subprocess.TimeoutExpired:
        print('VulnScout processing deadline exceeded; stopping its process group', file=sys.stderr, flush=True)
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            child.wait(timeout={TIMEOUT_GRACE})
        except subprocess.TimeoutExpired:
            pass
        # Descendants may outlive the entrypoint or ignore SIGTERM.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        sys.exit({PROCESSING_TIMED_OUT})
    sys.exit(result if result >= 0 else 128 - result)
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
        timeout: float = DEFAULT_OPERATION_TIMEOUT,
    ) -> None:
        self.engine, self.name = engine, name
        self.info, self.warn, self.debug = info, warn, debug
        self.timeout = timeout
        self._interface: BackendInterface | None = None

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
            f'{{{{range .Mounts}}}}{{{{if eq .Destination "{CACHE_DIR}"}}}}{{{{.Source}}}}{{{{end}}}}{{{{end}}}}',
            self.name,
        ], f'Inspecting container "{self.name}"', capture_output=True)
        return output.stdout.strip()

    def wait_ready(self, retries: int = 10) -> None:
        last_error = None
        for _ in range(retries):
            try:
                run_command(
                    container_exec(self.engine, self.name, ['true']),
                    f'Probing container "{self.name}"', capture_output=True, timeout=5,
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
            self.check_processing_support()
            if state != 'running':
                command = [self.engine, 'start', self.name]
                self.info(f'Starting existing VulnScout container: {shlex.join(command)}')
                run_command(command, f'Starting container "{self.name}"', timeout=300)
                self.wait_ready()
            return
        os.makedirs(data_dir, exist_ok=True)
        command = [
            self.engine, 'run', '-d', '--name', self.name,
            '-p', f'{port}:{port}', '-e', f'FLASK_RUN_HOST={host}', '-e', f'FLASK_RUN_PORT={port}',
            '-v', f'{data_dir}:{CACHE_DIR}', image, 'daemon',
        ]
        self.info(f'Starting VulnScout container: {shlex.join(command)}')
        run_command(command, f'Starting VulnScout container from image {image}', timeout=300)
        self.wait_ready()
        validate_cache_mount(self.data_mount(), data_dir)
        self.check_processing_support()

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
            run_command(command, f'Staging SPDX file {spdx_file}', timeout=self.timeout)
            staged.append(staged_path)
        return staged

    def check_processing_support(self) -> BackendInterface:
        if self._interface is None:
            result = run_command([
                self.engine, 'inspect', '--format',
                '{{json .Config.Labels}}', self.name,
            ], 'Reading VulnScout interface contract', capture_output=True)
            self._interface = resolve_interface(result.stdout.strip())
            if self._interface is V023_INTERFACE:
                self.info('Using the built-in VulnScout v0.23 compatibility adapter')
        return self._interface

    def run_processing(
        self, arguments: Sequence[str], directory: str, *, accepted_codes: Sequence[int] = (0,),
    ) -> int:
        interface = self.check_processing_support()
        return self.run_backend(
            [*interface.entrypoint, *arguments], lock=True, accepted_codes=accepted_codes,
            environment={'VULNSCOUT_INPUTS_DIR': f'{directory}/inputs'},
        ).returncode

    def run_backend(
        self, arguments: Sequence[str], operation: str = 'VulnScout', *,
        environment: Mapping[str, str] | None = None, workdir: str | None = None,
        capture_output: bool = False, accepted_codes: Sequence[int] = (0,),
        lock: bool = False, timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        interface = self.check_processing_support()
        duration = self.timeout if timeout is None else timeout
        command = container_exec(
            self.engine, self.name,
            [*interface.python, '-c', PROCESSING_LOCK_PROGRAM, PROCESSING_LOCK if lock else '',
             f'{duration:g}', *arguments],
            environment=environment, workdir=workdir or interface.workdir,
        )
        self.debug(f'Running VulnScout command: {shlex.join(command)}')
        try:
            return run_command(
                command, operation, accepted_codes=accepted_codes, capture_output=capture_output,
                timeout=duration + TIMEOUT_GRACE + MANAGEMENT_TIMEOUT,
            )
        except VulnScoutError as error:
            if lock and error.returncode == LOCK_BUSY:
                raise VulnScoutError(
                    'Another west vulnscout operation is processing this cache. '
                    'Retry after it finishes.'
                ) from error
            if error.returncode == PROCESSING_TIMED_OUT:
                raise VulnScoutError(
                    f'{operation} processing timed out after {duration:g} seconds; '
                    'its process group was stopped. Increase --timeout for longer operations.',
                    timed_out=True, stdout=error.stdout, stderr=error.stderr,
                ) from error
            raise
