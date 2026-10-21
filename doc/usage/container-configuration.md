# Container Lifecycle and Configuration

## Direct container mode

By default, the extension runs VulnScout through `docker exec` or `podman exec`.
It reuses a running container, starts a stopped container, or creates one if
needed.

Use `--container-engine {auto,docker,podman}` to select the engine. Auto mode
prefers Podman, then Docker. `--container-name NAME` changes the default
container name, `vulnscout`. Newly created containers publish the native
`VULNSCOUT_ENV_FLASK_RUN_PORT` on the same host port (7275 by default). See
{ref}`custom-port-and-browser-url`
for configuration and existing-container limitations.

## Persistent cache

In direct mode, newly created containers mount
`<build-dir>/../.vulnscout/cache` to `/cache/vulnscout`. For example, with
`-d demo/mbedtls_sbom/build`, the database is stored at
`demo/mbedtls_sbom/.vulnscout/cache/vulnscout.db`.

Use `--vulnscout-data-dir /path/to/data` to override the host cache location.

An existing container keeps its original mount. Inspect it with:

```sh
podman inspect vulnscout \
  --format '{{range .Mounts}}{{if eq .Destination "/cache/vulnscout"}}{{.Source}}{{end}}{{end}}'
```

Use that host path as `--vulnscout-data-dir` when continuing the workflow.
Imports and refreshes warn if an existing container uses a different cache;
report generation refuses the mismatch.

## Image selection

`--vulnscout-image` is interpreted as `repo[:tag]`. If the tag is omitted, the
command uses `VULNSCOUT_VERSION` (or the legacy `VULNSCOT_VERSION`), defaulting
to `v0.23`. The default image is `docker.io/sflinux/vulnscout:v0.23`.

For example, add `--vulnscout-image sfl:custom` when creating a container from
a locally built image. Reusing an existing container does not replace its image.

## Stop the container

Stop and remove the container immediately:

```sh
west vulnscout stop --container-engine podman
```

The existing `west vulnscout --stop` syntax remains supported. Both forms
accept `--container-engine`, `--container-name`, and `--vulnscout-cmd`;
neither requires a build directory. Stopping preserves host-mounted data.

To stop the container after a successful one-shot import:

```sh
west vulnscout -d demo/mbedtls_sbom/build \
  --container-engine podman --no-generate \
  --project zephyr_demo --variant mbedtls_native_sim \
  --stop-after-run
```

`--stop-after-run` also works with refresh and report operations, but cannot
be combined with `--serve`. Do not stop a shared container without coordinating
with its other users.

## Wrapper mode

Use the VulnScout wrapper script instead of direct container execution:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build \
  --project zephyr_demo --variant mbedtls_native_sim \
  --vulnscout-cmd /path/to/vulnscout \
  --vulnscout-image sfl:custom \
  --serve --dev
```

`--dev` is supported only in wrapper mode. The `report` action requires direct
container mode and rejects `--vulnscout-cmd`.
