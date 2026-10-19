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

## Repository layout

- `west-commands.yml`: command registration for West
- `scripts/west_commands/vulnscout.py`: command implementation

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

Build the application with `CONFIG_BUILD_OUTPUT_META=y` first. Open
http://localhost:7275/ to follow scanning progress. `--perform-scan` passes
`--perform-scans all` to VulnScout in both direct container and wrapper modes.
Without this flag, the command imports the SBOM without requesting a full
scan, except for the refresh-only mode described below.
Full scans may require network access and scanner credentials.
Do not start a second web server if one is already running in the container.

In direct mode, VulnScout data is persisted on the host by mounting
`<build-dir>/../.vulnscout/cache` to `/cache/vulnscout` in the container. For
example with `-d demo/mbedtls_sbom/build`, the database is stored at
`demo/mbedtls_sbom/.vulnscout/cache/vulnscout.db`.

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
