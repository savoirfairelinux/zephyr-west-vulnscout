# zephyr-west-vulnscout

West extension command for Zephyr that generates SPDX 3 SBOMs and imports them
into VulnScout for vulnerability analysis.

## What it provides

- `west vulnscout`
  - Generates SPDX SBOM files via `west spdx` (default: SPDX 3.0)
  - Imports SBOM files into VulnScout using `--add-spdx`
  - Uses direct `docker exec`/`podman exec` by default
  - Supports optional VulnScout flags like `--serve` and `--dev`
  - Supports optional wrapper mode via `--vulnscout-cmd`
- `west vulnscout report`
  - Generates reports from stored results without importing or rescanning
  - Copies the selected report from the container to a host directory
- `west vulnscout export`
  - Exports stored variant data as SPDX 3.0, SPDX 2.3, CycloneDX, or OpenVEX
  - Copies the exported file to a host directory without importing or rescanning

## Repository layout

- `west-commands.yml`: command registration for West
- `scripts/west_commands/vulnscout.py`: West integration, CLI/help, and workflow orchestration
- `scripts/west_commands/vulnscout_helpers/options.py`: configuration, validation, and command builders
- `scripts/west_commands/vulnscout_helpers/container.py`: container lifecycle, cache protection, staging, and locking
- `scripts/west_commands/vulnscout_helpers/process.py`: subprocess execution and shared errors
- `scripts/west_commands/vulnscout_helpers/backend.py`: image-interface validation and v0.23 compatibility

The helper package is independent of West. West's extension loader makes it
importable alongside the command, without requiring the repository as the
working directory or modifying `PYTHONPATH`.

## Add to your West workspace

Add this repository as a project in your West manifest and register
`west-commands.yml`:

```yaml
manifest:
  projects:
    - name: zephyr-west-vulnscout
      url: https://github.com/ValentinBoudevinSFL/zephyr-west-vulnscout
      revision: main
      path: zephyr-west-vulnscout
      west-commands: west-commands.yml
```

Then update and check command availability:

```sh
west update zephyr-west-vulnscout
west help vulnscout
```

The help groups options by feature and includes examples for imports, scanning,
refresh, reports, exports, policy checks, and container lifecycle. With no
action, the command generates and imports an SBOM; scanning requires
`--perform-scan`. The `report` and `export` actions use stored data instead.

## Example usage

From your Zephyr workspace root:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build \
  --project default \
  --variant zephyr_demo \
  --serve
```

In direct container mode, pressing Ctrl+C while `--serve` is running stops the
VulnScout container before exiting.

To generate the SBOM, run all vulnerability scanners, and serve the web
interface:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build \
  --container-engine podman \
  --project zephyr_demo \
  --variant mbedtls_native_sim \
  --perform-scan --serve
```

Build the application with `CONFIG_BUILD_OUTPUT_META=y` first. In direct mode,
follow initial processing in the terminal; the UI starts afterward at
http://localhost:7275/. `--perform-scan` passes
`--perform-scans all` to VulnScout in both direct container and wrapper modes.
Without this flag, the command imports the SBOM without requesting a full
scan, except for the refresh-only mode described below.
Full scans may require network access and scanner credentials.
Do not start a second web server if one is already running in the container.

Direct mode accepts `VULNSCOUT_ENV_FLASK_RUN_HOST` and
`VULNSCOUT_ENV_FLASK_RUN_PORT`, matching `meta-vulnscout`, with native
`FLASK_RUN_HOST`/`FLASK_RUN_PORT` fallbacks. New containers publish the selected
port on the same host port; existing containers retain their original mappings.
See
[Custom port and browser URL](doc/interactive-mode.md#custom-port-and-browser-url)
for an example and hostname/TLS considerations.

In direct mode, VulnScout data is persisted on the host by mounting
`<build-dir>/../.vulnscout/cache` to `/cache/vulnscout` in the container. For
example with `-d demo/mbedtls_sbom/build`, the database is stored at
`demo/mbedtls_sbom/.vulnscout/cache/vulnscout.db`.

Every direct data operation refuses a mismatched or missing cache mount.
Imports use private inputs and fail immediately if another West invocation is
processing the same cache. Published v0.23 images work without backend changes
through a built-in, version-specific adapter. Images can optionally declare the
`io.vulnscout.interface` label to describe their commands and capabilities.
Unknown versions without a declaration and invalid declarations are rejected.
Wrapper and other native clients need separate coordination.
See [Container Lifecycle and Configuration](doc/container-configuration.md).

If SPDX files already exist and you only want to import them:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build \
  --no-generate \
  --project default \
  --variant zephyr_demo \
  --serve
```

To refresh vulnerability data already stored for an existing project and
open the web interface without generating or importing another SBOM:

```sh
west vulnscout -d demo/mbedtls_sbom/build \
  --container-engine podman \
  --vulnscout-image sfl:custom \
  --project zephyr_demo --variant mbedtls_native_sim \
  --refresh-vulnerability-data --serve
```

Omit `--serve` if the web server is already running. The build directory
selects the persistent cache; SPDX files are not required for this mode.
This refreshes stored EPSS, NVD, EUVD, and GHSA data; it does not rerun
vulnerability scanners. Combine with `--perform-scan` to generate and import
an SBOM, scan it, and enrich the newly encountered vulnerabilities instead.

Always pass the same `--project` and `--variant` when continuing a workflow.
Omitting them selects `default/default`; `--serve` alone still generates and
imports an SBOM rather than acting as a view-only command.

### Monitor vulnerabilities

Evaluate a vulnerability policy after importing the SBOM:

```sh
west vulnscout -d demo/mbedtls_sbom/build \
  --container-engine podman \
  --project zephyr_demo --variant mbedtls_native_sim \
  --match-condition 'cvss >= 9.0 and (pending or affected)'
```

Exit codes distinguish no match (`0`), execution errors (`1`), and a policy
match (`2`). Add `--perform-scan` to request all scanners before evaluation.
Conditions use stored metadata unless it is explicitly refreshed, and cannot
be combined with `--serve`.
See [Monitor Vulnerabilities](doc/monitor-vulnerabilities.md) for tokens,
examples, scope, refresh behavior, and CI integration.

### Generate a report

After importing and scanning a project, generate a report from its stored data:

```sh
west vulnscout report -d demo/mbedtls_sbom/build \
  --container-engine podman \
  --project zephyr_demo --variant mbedtls_native_sim \
  --template summary.adoc --format html \
  --output-dir demo/mbedtls_sbom/reports
```

This writes `summary.adoc.html` on the host. Use `--format pdf` for
`summary.adoc.pdf`, or omit `--format` to retain the template's native format.
The default template is `summary.adoc`; other installed templates include
`all_assessments.adoc`. Templates must be installed names, not host paths.
Conversion to HTML/PDF requires an `.adoc` template and the corresponding
conversion tools in the VulnScout image.

The default output directory is `<build-dir>/vulnscout-reports`. The build
directory selects the same persistent cache as a scan; no SPDX files are needed.
Use the same `--project`, `--variant`, and, if applicable,
`--vulnscout-data-dir` as the original import. Reporting refuses a container
mounted to a different cache rather than exporting another database.

Reports use direct Docker/Podman mode; `--vulnscout-cmd` is not supported for this
action. A running web server is reused without restarting it. The command does
not generate/import SBOMs, refresh vulnerability data, or run scanners, and
rejects options requesting those operations. `--stop-after-run` remains
available. An unavailable report command, template, or converter causes an
error instead of returning an old output file.

For a custom Jinja2/AsciiDoc template named `my-report.adoc`, install it in the
container's persistent template directory first:

```sh
podman exec vulnscout mkdir -p /cache/vulnscout/templates
podman cp my-report.adoc vulnscout:/cache/vulnscout/templates/my-report.adoc
```

Then select it by filename. Replace `/path/to/existing/cache` with the host
directory mounted at `/cache/vulnscout` in that container:

```sh
west vulnscout report -d demo/mbedtls_sbom/build \
  --container-engine podman \
  --vulnscout-data-dir /path/to/existing/cache \
  --project zephyr_demo --variant mbedtls_native_sim \
  --template my-report.adoc --format html --output-dir reports
```

The generated report is `reports/my-report.adoc.html`.

### Export stored SBOM data

```sh
west vulnscout export -d demo/mbedtls_sbom/build \
  --container-engine podman \
  --project zephyr_demo --variant mbedtls_native_sim \
  --format spdx3 --output-dir exports
```

This writes `exports/sbom_spdx_v3_0.spdx.json`. Use `--format spdx2` for SPDX 2.3,
`cdx14`, `cdx15`, or `cdx16` for CycloneDX, or `openvex` for an OpenVEX document.
The default format is `spdx3`; the default directory is
`<build-dir>/vulnscout-exports`.

Export uses the existing database without generating/importing an SBOM or
running scanners. Keep the same project, variant, and cache as the original
import; pass `--vulnscout-data-dir /path/to/existing/cache` when needed.
Missing or ambiguous scope selections are rejected. This action requires
direct container mode, not `--vulnscout-cmd`.
See [Exporting SBOM Files](doc/exports.md) for filenames and examples.

### Container lifecycle

To stop the VulnScout container cleanly after task completion:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build \
  --no-generate \
  --project default \
  --variant zephyr_demo \
  --stop-after-run
```

To stop the container immediately:

```sh
west vulnscout stop
```

The existing `west vulnscout --stop` syntax remains supported. Both forms
accept `--container-engine`, `--container-name`, and `--vulnscout-cmd`;
neither requires a build directory. Stopping removes the container, but
preserves its host-mounted data.

If you prefer using the VulnScout wrapper script instead of direct container
exec mode:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build \
  --project default \
  --variant zephyr_demo \
  --vulnscout-cmd /home/vboudevin/Documents/vs/vulnscout/vulnscout \
  --vulnscout-image sfl:custom \
  --serve --dev
```

`--vulnscout-image` is interpreted as `repo[:tag]`. If the tag is omitted,
the command uses `VULNSCOUT_VERSION` (or `VULNSCOT_VERSION`), defaulting to
`v0.23`. The default image is `docker.io/sflinux/vulnscout:v0.23`.

Use `--vulnscout-data-dir /path/to/data` to override the default data location.

## Tests

Run the unit suite from this repository:

```sh
python -m unittest discover -s tests -q
```

The container smoke test is opt-in and requires a local compatible image and
generated Zephyr JSON-LD fixtures. It creates and removes its own uniquely named
container and temporary cache, with networking disabled; it does not use the
existing `vulnscout` container.

```sh
VULNSCOUT_INTEGRATION_IMAGE=docker.io/sflinux/vulnscout:v0.23 \
VULNSCOUT_INTEGRATION_SPDX_DIR=../demo/mbedtls_sbom/build/spdx \
python -m unittest discover -s tests -p test_vulnscout_integration.py -v
```

Set `VULNSCOUT_INTEGRATION_ENGINE=docker` to use Docker instead of Podman.
Use a locally available v0.23 image or one declaring a valid interface contract;
no backend rebuild or additional label is required for the published v0.23 image.
The smoke test covers native deadlines, cache refusal, lock contention, private-input cleanup,
variant selection, untouched shared inputs, and importing while an attached
web interface remains running.

## License

Copyright (C) 2025-2026 Savoir-faire Linux, Inc.

This repository is licensed under Apache-2.0. See LICENSE.

## Maintainer and Patches

Maintainer: Valentin Boudevin valentin.boudevin@savoirfairelinux.com

Submit patches and bug reports through the meta-vulnscout GitHub repository.
Each patch should include a clear commit message and a Signed-off-by line.

## Documentation

This repository includes Read the Docs configuration and Sphinx sources in the
same style as VulnScout and meta-vulnscout.

- Read the Docs config: .readthedocs.yaml
- Sphinx configuration: doc/conf.py
- Sphinx entry page: doc/index.rst

Build the HTML documentation from this repository's root:

```sh
python -m pip install -r doc/requirements.txt
python -m sphinx -a -b html doc doc/_build/html
```

Open `doc/_build/html/index.html`. The `-a` option rewrites every HTML page so
sidebar menus stay consistent after changing the documentation navigation.
