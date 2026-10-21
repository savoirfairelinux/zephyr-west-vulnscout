# Copyright (c) 2026
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Mapping, Sequence
import subprocess


class VulnScoutError(RuntimeError):
    def __init__(self, message: str, returncode: int | None = None) -> None:
        super().__init__(message)
        self.returncode = returncode


def run_command(
    command: Sequence[str], operation: str, *, capture_output: bool = False,
    env: Mapping[str, str] | None = None, accepted_codes: Sequence[int] = (0,),
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(command), check=True, capture_output=capture_output, text=True, env=env,
        )
    except subprocess.CalledProcessError as error:
        if error.returncode in accepted_codes:
            return subprocess.CompletedProcess(
                error.cmd, error.returncode, error.stdout, error.stderr,
            )
        details = (error.stderr or '').strip() if capture_output else ''
        message = f'{operation} failed with exit code {error.returncode}'
        if details:
            message += f': {details}'
        raise VulnScoutError(message, error.returncode) from error
    except OSError as error:
        raise VulnScoutError(f'{operation}: could not execute {command[0]}: {error}') from error
