# SBOM Generation and Import

## Generate and import an SBOM

Build the application with `CONFIG_BUILD_OUTPUT_META=y` first, then run from
your Zephyr workspace root:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout add \
  -d demo/mbedtls_sbom/build
```

By default, `add` generates SPDX 3.0 SBOMs using `west spdx` and imports
the matching files from `<build-dir>/spdx`:

- `*.jsonld`
- `*.spdx.json`
- `*.spdx`

Importing does not request a full vulnerability scan. See
[Vulnerability Scanning](vulnerability-scanning.md) to run the scanners too.
To convert stored data to SPDX 2.3, SPDX 3.0, or CycloneDX, see
[Exporting SBOM Files](exports.md).

## Projects, variants, and cache

Without `--project` and `--variant`, the command imports into `default/default`.
It does not infer either name from the build directory. To organize this
application's SBOM under a named project and variant, use the same command
with explicit names:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout add \
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
west vulnscout add -d demo/mbedtls_sbom/build \
  --no-generate --spdx-dir demo/mbedtls_sbom/build/spdx \
  --project zephyr_demo --variant mbedtls_native_sim
```

Use `--spdx /path/to/file.jsonld` to select an explicit file and skip generation
and directory discovery. Repeat the option for companion documents.
`--spdx-file` remains an alias. Import all West companion documents together
to retain their cross-document relationships.

## SPDX generation options

| Option | Purpose |
| --- | --- |
| `--spdx-dir PATH` | Change the generation/import directory. |
| `--spdx-version {3.0,3.1}` | Select the SPDX version; the default is 3.0. |
| `--namespace-prefix PREFIX` | Pass a namespace prefix to `west spdx`. |
| `--include-sdk` | Include the SDK in SPDX generation. |
| `--analyze-includes` | Analyze included header files during generation. |

SPDX 3.1 requires `spdx-python-model` bindings for `v3_1`. The extension retries
with SPDX 3.0 only when generation reports a specific missing-`v3_1` binding
exception. Build/metadata errors, missing executables or the entire model
package, permissions, timeouts, and unrecognized errors fail without a downgrade.
Experimental 3.1 generation output is captured for this diagnosis and displayed
when the command returns; default 3.0 generation continues streaming its output.

Use `--timeout SECONDS` to adjust the generation deadline. See
{ref}`operation-deadlines` for defaults
and the separate interactive-server behavior.

(migrating-existing-commands)=
## Migrating existing commands

West uses VulnScout v0.24's command-first syntax for the supported operations:
`add`, `scan`, `refresh`, `match-condition`, `serve`, `report`, `export`, and
`stop`. It does not expose every VulnScout maintenance or import command.
West's `add` handles Zephyr SPDX input, with generation enabled unless
`--no-generate` or explicit `--spdx` files are supplied.

Legacy workflow syntax remains accepted with a deprecation warning:

| Legacy invocation | Command-first equivalent |
| --- | --- |
| `west vulnscout [options]` | `west vulnscout add [options]` |
| `west vulnscout --perform-scan [options]` | Run `add`, then `scan`, with the same scope and cache options. |
| `west vulnscout --refresh-vulnerability-data [options]` | `west vulnscout refresh [options]` |
| `west vulnscout --match-condition EXPR [options]` | Run `add`, then `match-condition EXPR`, with the same scope and cache options. |
| `west vulnscout --serve [options]` | Run `add`, then `serve`, with the same cache options. |
| `west vulnscout --stop` | `west vulnscout stop` |
| `west vulnscout report --template NAME [options]` | `west vulnscout report NAME [options]` |
| `west vulnscout export --format cdx16 [options]` | `west vulnscout export cdx [options]` |

Unlike the old combined workflows, `scan`, `refresh`, `match-condition`, and
`serve` do not ask West to generate or import an SBOM. Keep them separate from
generation/input options and legacy workflow flags.
Use `scan nvd osv`, `scan nvd,osv`, or `scan --nvd --osv` to select scanners.
An unqualified `scan` selects all scanners.

Scope options `-p`/`--project` and `-v`/`--variant` are accepted before or after
the command. West always selects exactly one variant, defaulting to project
`default` and variant `default`, even for `refresh` and `match-condition`.
This is deliberately narrower than some upstream commands' all-variant or
all-project defaults. `serve` opens the whole cache.

In wrapper mode, West invokes the new VulnScout subcommands rather than its
deprecated flags. Use an updated v0.24 wrapper. Direct mode continues to use
the container's supported internal entrypoint and Flask CLI.
