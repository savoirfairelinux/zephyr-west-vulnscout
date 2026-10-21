# Interactive Mode (Web UI)

## Import and serve

Generate and import an SBOM, then serve the web interface:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build \
  --container-engine podman \
  --project zephyr_demo --variant mbedtls_native_sim \
  --serve
```

Open http://localhost:7275/ and select project `zephyr_demo`, variant
`mbedtls_native_sim`.

`--serve` alone still generates and imports an SBOM; it is not a view-only
command. Use `--no-generate --serve` to import existing SPDX files instead.
Add `--perform-scan` to request a full vulnerability scan as well.

To refresh existing data without another import, use
[`--refresh-vulnerability-data --serve`](vulnerability-data.md).

## Reuse a running web interface

If the container is already serving the interface, omit `--serve` from import,
scan, and refresh commands. Do not start a second web server in the same
container. Report generation also reuses the container without restarting the
web server.

## Stop serving

In direct container mode, pressing Ctrl+C while `--serve` is running stops the
VulnScout container before exiting, including its other services. Do not stop
a shared container without coordinating with its other users.

`--serve` cannot be combined with `--stop-after-run`. See
[Container Lifecycle and Configuration](container-configuration.md) for explicit
stop commands and wrapper mode.
