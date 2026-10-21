# SBOM Generation and Import

## Generate and import an SBOM

Build the application with `CONFIG_BUILD_OUTPUT_META=y` first, then run from
your Zephyr workspace root:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build
```

By default, the command generates SPDX 3.0 SBOMs using `west spdx` and imports
the matching files from `<build-dir>/spdx`:

- `*.jsonld`
- `*.spdx.json`
- `*.spdx`

Importing does not request a full vulnerability scan. See
[Vulnerability Scanning](vulnerability-scanning.md) to run the scanners too.

## Projects, variants, and cache

Without `--project` and `--variant`, the command imports into `default/default`.
It does not infer either name from the build directory. To organize this
application's SBOM under a named project and variant, use the same command
with explicit names:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build \
  --project zephyr_demo --variant mbedtls_native_sim
```

Keep the same project and variant when importing updated SBOMs, scanning,
refreshing vulnerability data, or generating reports. The other feature guides
use `zephyr_demo` and `mbedtls_native_sim` consistently.

The build directory also selects the default persistent cache. When reusing
an existing container, check its cache location as described in
[Container Lifecycle and Configuration](container-configuration.md).

## Reuse existing SPDX files

Skip generation and import files already present in the SPDX directory:

```sh
west vulnscout -d demo/mbedtls_sbom/build \
  --no-generate --spdx-dir demo/mbedtls_sbom/build/spdx \
  --project zephyr_demo --variant mbedtls_native_sim
```

Use `--spdx-file /path/to/file.jsonld` to select an explicit file. Repeat the
option for companion documents; when explicit files are supplied, directory
discovery is skipped. Import all West companion documents together to retain
their cross-document relationships.

## SPDX generation options

| Option | Purpose |
| --- | --- |
| `--spdx-dir PATH` | Change the generation/import directory. |
| `--spdx-version {3.0,3.1}` | Select the SPDX version; the default is 3.0. |
| `--namespace-prefix PREFIX` | Pass a namespace prefix to `west spdx`. |
| `--include-sdk` | Include the SDK in SPDX generation. |
| `--analyze-includes` | Analyze included header files during generation. |

SPDX 3.1 requires `spdx-python-model` bindings for `v3_1`. If generation fails
with 3.1 selected, the extension warns and retries with SPDX 3.0.
