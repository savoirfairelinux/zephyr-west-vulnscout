# Copyright (c) 2026
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Mapping, Sequence
import subprocess


MANAGEMENT_TIMEOUT = 30
DEFAULT_OPERATION_TIMEOUT = 3600


class VulnScoutError(RuntimeError):
    def __init__(
        self, message: str, returncode: int | None = None, *,
        stdout: str = '', stderr: str = '', timed_out: bool = False,
    ) -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stdout, self.stderr = stdout, stderr
        self.timed_out = timed_out


def output_text(value: str | bytes | None) -> str:
    return value.decode(errors='replace') if isinstance(value, bytes) else (value or '')


def run_command(
    command: Sequence[str], operation: str, *, capture_output: bool = False,
    env: Mapping[str, str] | None = None, accepted_codes: Sequence[int] = (0,),
    timeout: float | None = MANAGEMENT_TIMEOUT,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(command), check=True, capture_output=capture_output, text=True, env=env,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        stdout, stderr = output_text(error.stdout), output_text(error.stderr)
        details = f': {stderr.strip()}' if stderr.strip() else ''
        raise VulnScoutError(
            f'{operation} timed out after {timeout:g} seconds{details}',
            stdout=stdout, stderr=stderr, timed_out=True,
        ) from error
    except subprocess.CalledProcessError as error:
        if error.returncode in accepted_codes:
            return subprocess.CompletedProcess(
                error.cmd, error.returncode, error.stdout, error.stderr,
            )
        stdout, stderr = output_text(error.stdout), output_text(error.stderr)
        details = stderr.strip() if capture_output else ''
        message = f'{operation} failed with exit code {error.returncode}'
        if details:
            message += f': {details}'
        raise VulnScoutError(message, error.returncode, stdout=stdout, stderr=stderr) from error
    except OSError as error:
        raise VulnScoutError(f'{operation}: could not execute {command[0]}: {error}') from error
