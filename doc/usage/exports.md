# Exporting SBOM Files

## Export stored project data

After importing an SBOM, export the selected project's variant from VulnScout:

```sh
west vulnscout export -d demo/mbedtls_sbom/build \
  --container-engine podman \
  --project zephyr_demo --variant mbedtls_native_sim \
  --format spdx3 --output-dir exports
```

This writes `exports/sbom_spdx_v3_0.spdx.json` on the host. Export reads the
existing database; it does not regenerate or import an SBOM, refresh data, or
run scanners. A previous vulnerability scan is not required.

Unlike the original `west spdx` output, these files are rendered from
VulnScout's stored data. Supported formats include vulnerability and assessment
information where the output format supports it.

## Output formats

| `--format` | Format | Output filename |
| --- | --- | --- |
| `spdx3` | SPDX 3.0 JSON-LD (default) | `sbom_spdx_v3_0.spdx.json` |
| `spdx2` | SPDX 2.3 JSON | `sbom_spdx_v2_3.spdx.json` |
| `cdx14` | CycloneDX 1.4 JSON | `sbom_cyclonedx_v1_4.cdx.json` |
| `cdx15` | CycloneDX 1.5 JSON | `sbom_cyclonedx_v1_5.cdx.json` |
| `cdx16` | CycloneDX 1.6 JSON | `sbom_cyclonedx_v1_6.cdx.json` |
| `openvex` | OpenVEX vulnerability/assessment document, not a component inventory | `openvex.json` |

For SPDX 2.3, run the same command with `--format spdx2`:

```sh
west vulnscout export -d demo/mbedtls_sbom/build \
  --container-engine podman \
  --project zephyr_demo --variant mbedtls_native_sim \
  --format spdx2 --output-dir exports
```

`--spdx-version` configures [SBOM generation](sbom-generation.md), not export.
The export backend currently supports SPDX 3.0 and 2.3, not SPDX 3.1.

## Scope, cache, and output directory

Use the same `--project`, `--variant`, and cache settings as the original import.
The default selection is `default/default`; a missing or ambiguous selection
is rejected before export rather than falling back to other projects or variants.
The selected variant is passed to VulnScout by UUID.

When reusing a container whose cache differs from the build directory's
default, specify its host mount explicitly:

```sh
west vulnscout export -d demo/mbedtls_sbom/build \
  --container-engine podman \
  --vulnscout-data-dir /path/to/existing/cache \
  --project zephyr_demo --variant mbedtls_native_sim \
  --format cdx16 --output-dir exports
```

See [Container Lifecycle and Configuration](container-configuration.md) for
inspecting the mount. Export refuses a different or missing cache mount.

The default output directory is `<build-dir>/vulnscout-exports`. Files are copied
from a unique temporary directory in the container, so a failed export cannot
return a file left by an earlier invocation.

## Container behavior

Export supports direct Docker/Podman mode, not `--vulnscout-cmd` wrapper mode.
It reuses the container without restarting the web server. Add
`--stop-after-run` to stop the container after a successful export.

An unsupported backend command/format or a generation/copy failure produces an
error. Import, scan, refresh, serve, and report-template options cannot be
combined with `export`.
