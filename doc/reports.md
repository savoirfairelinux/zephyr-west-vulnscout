# Report Generation

## Generate a report from stored results

After importing and scanning a project, generate a report from its stored data:

```sh
west vulnscout report -d demo/mbedtls_sbom/build \
  --container-engine podman \
  --project zephyr_demo --variant mbedtls_native_sim \
  --template summary.adoc --format html \
  --output-dir demo/mbedtls_sbom/reports
```

This writes `summary.adoc.html` on the host. Reporting does not generate/import
SBOMs, refresh vulnerability data, or run scanners. Options requesting those
operations are rejected.

## Templates, formats, and output

| Option | Purpose |
| --- | --- |
| `--template NAME` | Select an installed template; the default is `summary.adoc`. |
| `--format {html,pdf}` | Convert an AsciiDoc template to HTML or PDF. |
| `--output-dir PATH` | Select the host directory; the default is `<build-dir>/vulnscout-reports`. |

Without `--format`, the report retains the template's native format. For
`summary.adoc`, the output filenames are `summary.adoc`, `summary.adoc.html`,
or `summary.adoc.pdf`.

Conversion requires an `.adoc` template and the corresponding conversion tools
in the VulnScout image. Other installed templates include
`all_assessments.adoc`. For your own templates and images, see
[Writing Report Templates](templates.md).

## Select the database

The build directory selects the same default persistent cache as a scan; no
SPDX files are needed. Use the same `--project`, `--variant`, and, if applicable,
`--vulnscout-data-dir` as the original import.

Reporting refuses a container mounted to a different cache rather than
exporting another database. See
[Container Lifecycle and Configuration](container-configuration.md) for
inspecting the host mount.

## Container behavior and errors

Reports use direct Docker/Podman mode; `--vulnscout-cmd` is not supported for
this action. A running web server is reused without restarting it.
`--stop-after-run` remains available.

An unavailable report command, template, or converter causes an error instead
of returning an old output file.
