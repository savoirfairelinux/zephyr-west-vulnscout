# zephyr-west-vulnscout

West extension command for Zephyr that generates SPDX 3 SBOMs and imports them
into VulnScout for vulnerability analysis.

Full documentation: [Read the Docs](https://zephyr-west-vulnscout.readthedocs.io/en/latest/).

## VulnScout workflow

The extension connects Zephyr's SPDX output to the VulnScout workflow:

![VulnScout workflow: Import, Enrich, Assess, Enforce, and Share, with optional AI assistance during assessment.](https://raw.githubusercontent.com/savoirfairelinux/vulnscout/main/doc/source/_static/vulnscout-pipeline.svg)

## What it provides

- **Generate and import:** `west vulnscout` generates SPDX SBOMs via `west spdx`
  (default: SPDX 3.0) and imports them. Add `--no-generate` to reuse existing files.
- **Scan:** `west vulnscout --perform-scan` imports the SBOM and runs all
  vulnerability scanners.
- **Refresh:** `west vulnscout --refresh-vulnerability-data` updates stored
  vulnerability metadata without importing or rescanning.
- **Assess:** `west vulnscout --serve` opens the VulnScout web interface after
  processing, for reviewing findings and recording assessments.
- **Enforce:** `west vulnscout --match-condition 'EXPRESSION'` evaluates a
  vulnerability policy: exit `0` for no match, `2` for a match, and `1` on errors.
- **Report:** `west vulnscout report` generates reports from stored results and
  copies them to the host without importing or rescanning.
- **Export:** `west vulnscout export` writes stored variant data to the host as
  SPDX 3.0, SPDX 2.3, CycloneDX, or OpenVEX without importing or rescanning.

## Add to your West workspace

Add this repository as a project in your West manifest and register
`west-commands.yml`:

```yaml
manifest:
  projects:
    - name: zephyr-west-vulnscout
      url: https://github.com/savoirfairelinux/zephyr-west-vulnscout
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
action, the command generates and imports an SBOM. Scanning requires
`--perform-scan`. The `report` and `export` actions use stored data instead.

## Example usage

Run the following commands from your Zephyr workspace root.
Build the application with `CONFIG_BUILD_OUTPUT_META=y` first, and always use
the same build directory, project, variant, and cache when continuing a workflow.
The examples use project `zephyr_demo` and variant `mbedtls_native_sim`.
Omitting `--project` and `--variant` selects project `default` and variant `default`.

### 01 - Import

Generate SPDX files and import them without requesting a full vulnerability scan:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build \
  --project zephyr_demo \
  --variant mbedtls_native_sim
```

If SPDX files already exist, reuse them with `--no-generate`:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build \
  --project zephyr_demo \
  --variant mbedtls_native_sim \
  --no-generate
```

In direct mode, VulnScout data is persisted on the host by mounting
`<build-dir>/../.vulnscout/cache` to `/cache/vulnscout` in the container. For
example with `-d demo/mbedtls_sbom/build`, the database is stored at
`demo/mbedtls_sbom/.vulnscout/cache/vulnscout.db`.

See [Container Lifecycle and Configuration](doc/container-configuration.md)
for cache selection, concurrent operations, and image compatibility.

### 02 - Enrich

Import the existing SPDX files and run all vulnerability scanners:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build \
  --no-generate \
  --project zephyr_demo \
  --variant mbedtls_native_sim \
  --perform-scan
```

`--perform-scan` passes `--perform-scans all` to VulnScout in both direct and
wrapper modes. It still imports the SBOM. It is not a scan-only action.
Full scans may require network access and scanner credentials.

To refresh vulnerability metadata already stored for the selected variant
without generating or importing another SBOM:

```sh
west vulnscout -d demo/mbedtls_sbom/build \
  --project zephyr_demo --variant mbedtls_native_sim \
  --refresh-vulnerability-data
```

This updates metadata for known vulnerabilities without rerunning scanners.
No SPDX files are required. See [Vulnerability Data](doc/vulnerability-data.md)
for refresh behavior and combined scan options.

### 03 - Assess

Refresh stored metadata and open the web interface to review findings, record
assessment statuses, and document your rationale:

```sh
west vulnscout -d demo/mbedtls_sbom/build \
  --project zephyr_demo --variant mbedtls_native_sim \
  --refresh-vulnerability-data --serve
```

In direct mode, processing completes before the UI starts at
http://localhost:7275/. `--serve` alone still generates and imports an SBOM.
The refresh-only combination above avoids that, but updates stored metadata.
If the UI is already running, open its existing URL instead of starting another
web server. Imports and refreshes can run separately while the UI remains open.
Pressing Ctrl+C in an attached direct-mode session stops the container.

Assessment happens in VulnScout, not through a separate West assessment command.
The diagram's optional AI assistance belongs to VulnScout and requires separate
configuration. It is not enabled by `--serve`.

Direct mode accepts `VULNSCOUT_ENV_FLASK_RUN_HOST` and
`VULNSCOUT_ENV_FLASK_RUN_PORT`, with native `FLASK_RUN_HOST`/`FLASK_RUN_PORT`
fallbacks. New containers publish the selected port on the same host port.
Existing containers retain their original mappings.
See [Custom port and browser URL](doc/interactive-mode.md#custom-port-and-browser-url).

### 04 - Enforce

Evaluate a vulnerability policy against stored data after refreshing its
metadata, without generating or importing another SBOM:

```sh
west vulnscout -d demo/mbedtls_sbom/build \
  --project zephyr_demo --variant mbedtls_native_sim \
  --refresh-vulnerability-data \
  --match-condition 'cvss >= 9.0 and (pending or affected)'
```

Exit codes distinguish no match (`0`), execution errors (`1`), and a policy
match (`2`). Add `--perform-scan` to request all scanners before evaluation.
Conditions use stored metadata unless it is explicitly refreshed, and cannot
be combined with `--serve`.
See [Monitor Vulnerabilities](doc/monitor-vulnerabilities.md) for tokens,
examples, scope, refresh behavior, and CI integration.

### 05 - Share

Generate reports and export SBOM or VEX data from the same stored variant.

#### Generate a report

After importing and scanning a project, generate a report from its stored data:

```sh
west vulnscout report -d demo/mbedtls_sbom/build \
  --project zephyr_demo --variant mbedtls_native_sim \
  --template summary.adoc --format html \
  --output-dir demo/mbedtls_sbom/reports
```

This writes `demo/mbedtls_sbom/reports/summary.adoc.html`.
Reporting uses stored results without importing or rescanning.
See [Report Generation](doc/reports.md) for formats, cache selection, and errors,
and [Writing Report Templates](doc/templates.md) for custom-template installation.

#### Export stored SBOM data

```sh
west vulnscout export -d demo/mbedtls_sbom/build \
  --project zephyr_demo --variant mbedtls_native_sim \
  --format spdx3 --output-dir exports
```

This writes `exports/sbom_spdx_v3_0.spdx.json` without importing or rescanning.
Use `--format openvex` to export assessments as OpenVEX.
Both report and export require direct container mode rather than a wrapper.
See [Exporting SBOM Files](doc/exports.md) for supported formats, filenames,
scope selection, and errors.

## Container lifecycle and wrapper mode

To stop the VulnScout container cleanly after task completion:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build \
  --no-generate \
  --project zephyr_demo \
  --variant mbedtls_native_sim \
  --stop-after-run
```

To stop the container immediately:

```sh
west vulnscout stop
```

The existing `west vulnscout --stop` syntax remains supported. Both forms
accept `--container-engine`, `--container-name`, and `--vulnscout-cmd`.
Neither requires a build directory. Stopping removes the container, but
preserves its host-mounted data.

If you prefer using the VulnScout wrapper script instead of direct container
exec mode:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build \
  --project zephyr_demo \
  --variant mbedtls_native_sim \
  --vulnscout-cmd /path/to/vulnscout \
  --vulnscout-image sfl:custom \
  --serve --dev
```

`--vulnscout-image` is interpreted as `repo[:tag]`. If the tag is omitted,
the command uses `VULNSCOUT_VERSION` (or `VULNSCOT_VERSION`), defaulting to
`v0.24`. The default image is `docker.io/sflinux/vulnscout:v0.24`.

Use `--vulnscout-data-dir /path/to/data` to override the default data location.

## Repository layout

- `west-commands.yml`: command registration for West
- `scripts/west_commands/vulnscout.py`: West integration, CLI/help, and workflow orchestration
- `scripts/west_commands/vulnscout_helpers/options.py`: configuration, validation, and command builders
- `scripts/west_commands/vulnscout_helpers/container.py`: container lifecycle, cache protection, staging, and locking
- `scripts/west_commands/vulnscout_helpers/process.py`: subprocess execution and shared errors
- `scripts/west_commands/vulnscout_helpers/backend.py`: image-interface validation and compatibility

## Tests

Run the unit suite from this repository:

```sh
python -m unittest discover -s tests -q
```

The container smoke test is opt-in and requires a local compatible image and
generated Zephyr JSON-LD fixtures. It creates and removes its own uniquely named
container and temporary cache, with networking disabled. It does not use the
existing `vulnscout` container.

```sh
VULNSCOUT_INTEGRATION_IMAGE=docker.io/sflinux/vulnscout:v0.24 \
VULNSCOUT_INTEGRATION_SPDX_DIR=../demo/mbedtls_sbom/build/spdx \
python -m unittest discover -s tests -p test_vulnscout_integration.py -v
```

Set `VULNSCOUT_INTEGRATION_ENGINE=docker` to use Docker instead of Podman.
Use a locally available v0.24 image or one declaring a valid interface contract.
No backend rebuild or additional label is required for these published images.
The smoke test covers native deadlines, cache refusal, lock contention, private-input cleanup,
variant selection, untouched shared inputs, and importing while an attached
web interface remains running.

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

## Maintainer and Patches

Maintainer: Valentin Boudevin valentin.boudevin@savoirfairelinux.com

Submit patches and bug reports through the
[zephyr-west-vulnscout GitHub repository](https://github.com/savoirfairelinux/zephyr-west-vulnscout).
Each patch should include a clear commit message and a Signed-off-by line.

## License

Copyright (C) 2025-2026 Savoir-faire Linux, Inc.

This repository is licensed under Apache-2.0. See LICENSE.
