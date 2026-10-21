# Usage

From your Zephyr workspace root:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build \
  --project default \
  --variant zephyr_demo \
  --serve
```

In direct mode, VulnScout data is persisted on the host by mounting
`<build-dir>/../.vulnscout/cache` to `/cache/vulnscout` in the container. For
example with `-d demo/mbedtls_sbom/build`, the database is stored at
`demo/mbedtls_sbom/.vulnscout/cache/vulnscout.db`.

Generate the SBOM, run all vulnerability scanners, and start the web interface:

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

If SPDX files already exist and you only want to import them:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build \
  --no-generate \
  --project default \
  --variant zephyr_demo \
  --serve
```

Refresh stored vulnerability data and open the web interface without generating
or importing another SBOM:

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

## Generate a report

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

Stop the VulnScout container cleanly after task completion:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build \
  --no-generate \
  --project default \
  --variant zephyr_demo \
  --stop-after-run
```

Stop the container immediately:

```sh
west vulnscout stop
```

The existing `west vulnscout --stop` syntax remains supported. Both forms
accept `--container-engine`, `--container-name`, and `--vulnscout-cmd`;
neither requires a build directory. Stopping removes the container, but
preserves its host-mounted data.

Optional wrapper mode (instead of direct container exec):

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

The command generates SPDX 3.1 SBOM files with west spdx and then imports all
matching files from the SPDX output directory:

- *.jsonld
- *.spdx.json
- *.spdx
