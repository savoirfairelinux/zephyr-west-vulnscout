# Copyright (c) 2026
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
import math
import os
import pathlib
import re
import uuid

from .process import VulnScoutError


# Keep defaults aligned with the VulnScout wrapper script.
VULNSCOUT_IMAGE_REPO = os.environ.get('VULNSCOUT_IMAGE_REPO', 'docker.io/sflinux/vulnscout')
VULNSCOUT_VERSION = (
    os.environ.get('VULNSCOUT_VERSION')
    or os.environ.get('VULNSCOT_VERSION')
    or 'v0.23'
)
DEFAULT_VULNSCOUT_IMAGE = f'{VULNSCOUT_IMAGE_REPO}:{VULNSCOUT_VERSION}'
VULNSCOUT_ENV_FLASK_RUN_HOST = os.environ.get(
    'VULNSCOUT_ENV_FLASK_RUN_HOST', os.environ.get('FLASK_RUN_HOST', '0.0.0.0')
)
VULNSCOUT_ENV_FLASK_RUN_PORT = os.environ.get(
    'VULNSCOUT_ENV_FLASK_RUN_PORT', os.environ.get('FLASK_RUN_PORT', '7275')
)
SBOM_EXPORT_FILES = {
    'spdx3': 'sbom_spdx_v3_0.spdx.json',
    'spdx2': 'sbom_spdx_v2_3.spdx.json',
    'cdx14': 'sbom_cyclonedx_v1_4.cdx.json',
    'cdx15': 'sbom_cyclonedx_v1_5.cdx.json',
    'cdx16': 'sbom_cyclonedx_v1_6.cdx.json',
    'openvex': 'openvex.json',
}


def positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError('timeout must be a positive, finite number of seconds') from error
    if not math.isfinite(timeout) or not 0 < timeout <= 86400:
        raise argparse.ArgumentTypeError('timeout must be greater than 0 and at most 86400 seconds')
    return timeout


def spdx31_bindings_unavailable(stderr: str) -> bool:
    patterns = (
        r"""^AttributeError: module ['"]spdx_python_model['"] has no attribute ['"]v3_1['"](?:\..*)?$""",
        r"""^ModuleNotFoundError: No module named ['"]spdx_python_model\.v3_1['"]$""",
        r"""^ImportError: cannot import name ['"]v3_1['"] from ['"]spdx_python_model['"](?: .*)?$""",
    )
    lines = stderr.rstrip().splitlines()
    return bool(lines) and any(re.fullmatch(pattern, lines[-1]) for pattern in patterns)


def web_server_settings(host: str, raw_port: str) -> tuple[str, str]:
    message = 'VULNSCOUT_ENV_FLASK_RUN_PORT / FLASK_RUN_PORT must be an integer between 1 and 65535'
    try:
        port = int(raw_port)
    except ValueError as error:
        raise VulnScoutError(message) from error
    if not 1 <= port <= 65535:
        raise VulnScoutError(message)
    if not host.strip():
        raise VulnScoutError('VULNSCOUT_ENV_FLASK_RUN_HOST / FLASK_RUN_HOST must not be empty')
    return host, str(port)


def configured_web_settings() -> tuple[str, str]:
    return web_server_settings(VULNSCOUT_ENV_FLASK_RUN_HOST, VULNSCOUT_ENV_FLASK_RUN_PORT)


def stored_output_spec(args: argparse.Namespace) -> tuple[list[str], str]:
    action = args.action
    if args.vulnscout_cmd:
        raise VulnScoutError(f'{action} uses direct container mode; omit --vulnscout-cmd')
    if any((
        args.perform_scan, args.refresh_vulnerability_data, args.serve, args.dev,
        args.match_condition, args.spdx_file, args.spdx_dir, args.no_generate,
        args.include_sdk, args.analyze_includes, args.namespace_prefix,
        args.spdx_version != '3.0',
    )):
        raise VulnScoutError(f'{action} cannot be combined with scan, import, refresh, or serve options')
    if action == 'export':
        output_format = args.format or 'spdx3'
        if output_format not in SBOM_EXPORT_FILES:
            raise VulnScoutError('export --format must be spdx3, spdx2, cdx14, cdx15, cdx16, or openvex')
        return ['export', '--format', output_format], SBOM_EXPORT_FILES[output_format]
    if args.format not in (None, 'html', 'pdf'):
        raise VulnScoutError('report --format must be html or pdf; use export for SBOM formats')
    template = args.template if args.template is not None else 'summary.adoc'
    if not template or template in ('.', '..') or pathlib.PurePosixPath(template).name != template:
        raise VulnScoutError('--template must be an installed template filename, not a path')
    if args.format and not template.endswith('.adoc'):
        raise VulnScoutError('--format requires an AsciiDoc (.adoc) template')
    return ['report', template], template + (f'.{args.format}' if args.format else '')


def export_variant_id(payload: str, project_name: str, variant_name: str) -> str:
    try:
        projects = json.loads(payload)
    except json.JSONDecodeError as error:
        raise VulnScoutError('Could not resolve export scope: list-projects returned invalid JSON') from error
    if not isinstance(projects, list) or any(not isinstance(project, dict) for project in projects):
        raise VulnScoutError('Could not resolve export scope: invalid project list')
    project = next((project for project in projects if project.get('name') == project_name), None)
    if project is None:
        raise VulnScoutError(f'Export project "{project_name}" not found')
    variants = project.get('variants')
    if not isinstance(variants, list) or any(not isinstance(variant, dict) for variant in variants):
        raise VulnScoutError('Could not resolve export scope: invalid variant list')
    matches = [variant for variant in variants if variant.get('name') == variant_name]
    if len(matches) != 1:
        raise VulnScoutError(f'Export variant "{variant_name}" must exist uniquely in project "{project_name}"')
    variant_id = matches[0].get('id')
    if not isinstance(variant_id, str):
        raise VulnScoutError('Could not resolve export scope: missing variant UUID')
    try:
        return str(uuid.UUID(variant_id))
    except ValueError as error:
        raise VulnScoutError('Could not resolve export scope: invalid variant UUID') from error


def validate_options(args: argparse.Namespace) -> None:
    if args.action not in ('report', 'export') and any((args.template, args.format, args.output_dir)):
        raise VulnScoutError(
            '--template, --format, and --output-dir require `west vulnscout report` '
            'or `west vulnscout export`'
        )
    if args.template is not None and args.action != 'report':
        raise VulnScoutError('--template requires `west vulnscout report`')
    if args.action in ('report', 'export') and args.stop:
        raise VulnScoutError(f'{args.action} cannot be combined with --stop')
    if args.action == 'stop' or args.stop:
        return
    if args.match_condition is not None and not args.match_condition.strip():
        raise VulnScoutError('--match-condition must not be empty')
    if args.match_condition and args.serve:
        raise VulnScoutError('--match-condition cannot be combined with --serve')
    if args.action not in ('report', 'export'):
        if args.dev and not args.vulnscout_cmd:
            raise VulnScoutError('--dev is only supported with --vulnscout-cmd (wrapper mode)')
        if args.serve and args.stop_after_run:
            raise VulnScoutError('--stop-after-run cannot be used with --serve')


def spdx_command(
    args: argparse.Namespace, build_dir: str, spdx_dir: str, version: str,
) -> list[str]:
    command = [
        'west', 'spdx', '--build-dir', build_dir, '--spdx-dir', spdx_dir,
        '--spdx-version', version,
    ]
    if args.namespace_prefix:
        command.extend(['--namespace-prefix', args.namespace_prefix])
    if args.include_sdk:
        command.append('--include-sdk')
    if args.analyze_includes:
        command.append('--analyze-includes')
    return command


def processing_arguments(args: argparse.Namespace, spdx_files: Sequence[str]) -> list[str]:
    result = ['--project', args.project, '--variant', args.variant]
    for path in spdx_files:
        result.extend(['--add-spdx', path])
    if args.perform_scan:
        result.extend(['--perform-scans', 'all'])
    if args.refresh_vulnerability_data:
        result.append('--refresh-vulnerability-data')
    if args.match_condition:
        result.extend(['--match-condition', args.match_condition])
    return result


def resolve_image(args: argparse.Namespace) -> str:
    repo, version = resolve_repo_and_version(args)
    return f'{repo}:{version}'


def resolve_data_dir(args: argparse.Namespace, build_dir: str) -> str:
    if args.vulnscout_data_dir:
        return os.path.abspath(args.vulnscout_data_dir)
    return os.path.abspath(os.path.join(build_dir, '..', '.vulnscout', 'cache'))


def resolve_repo_and_version(args: argparse.Namespace) -> tuple[str, str]:
    repo, version = VULNSCOUT_IMAGE_REPO, VULNSCOUT_VERSION
    if not args.vulnscout_image:
        return repo, version
    override = args.vulnscout_image.strip()
    if not override:
        return repo, version
    # Tag separator is ':' after the last '/'.
    if override.rfind(':') > override.rfind('/'):
        image_repo, image_tag = override.rsplit(':', 1)
        if image_repo and image_tag:
            return image_repo, image_tag
    return override, version


def image_environment(args: argparse.Namespace) -> dict[str, str]:
    repo, version = resolve_repo_and_version(args)
    return {
        'VULNSCOUT_IMAGE_REPO': repo,
        'VULNSCOUT_VERSION': version,
        'VULNSCOT_VERSION': version,
        'VULNSCOUT_IMAGE': f'{repo}:{version}',
    }
