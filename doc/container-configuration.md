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
All direct-mode imports, refreshes, reports, and exports refuse a different
or missing cache mount. Paths resolving to the same location, including
symlinks, are accepted. A stopped container's mount is checked before it is
started; a running container is not modified to switch caches.

(input-isolation-and-concurrent-processing)=
## Input isolation and concurrent processing

Each direct-mode processing invocation stages its files and native inputs in
a unique temporary directory inside the container. Only that directory is
removed afterward, including after a failed copy, processing error, or policy
match. Files pending in VulnScout's shared input directory are neither imported
nor deleted by the invocation.

Processing uses a nonblocking `flock` lock at
`/cache/vulnscout/.west-vulnscout.lock`. If another West invocation is processing
the same cache, the command fails immediately with an error asking you to retry.
This also coordinates participating containers mounting the same host cache.
The lock file may remain after processing; its presence does not mean the lock
is held. Do not delete it to clear a busy error.

Published v0.23 images work without rebuilding VulnScout or changing its backend.
When no `io.vulnscout.interface` label exists, West selects its built-in v0.23
adapter only if `org.opencontainers.image.version` is exactly `v0.23`.
The adapter centralizes that release's standard entrypoint, CLI prefix, Python
interpreter, and `/scan` working directory. This is an explicit version dependency,
not source-code probing or a guess based on an image tag.

Images can optionally declare version 1 of the `io.vulnscout.interface` OCI label,
including `isolated-inputs` and `python-fcntl` capabilities. A valid declaration
takes precedence over the adapter and supplies the commands and working directory
for relocated or newer images. Both modes use `/cache/vulnscout` as the public
persistent-cache mount. Processing requires isolated-input support and Python's
POSIX locking and process-group facilities; execution errors are reported normally.

Inspect the declaration with:

```sh
podman inspect vulnscout --format '{{json .Config.Labels}}'
```

West validates this metadata before staging files or starting a stopped
container. Unknown versions without a declaration are rejected. A present but
malformed or unsupported declaration is also rejected, even if the version label
is `v0.23`; it never silently falls back to the adapter. Custom images that change
the v0.23 layout must declare their actual interface rather than relying on the
standard adapter. Existing standard v0.23 containers need no recreation.

Direct-mode `--serve` starts the UI after processing and releasing the lock,
so later West imports can run while the interface remains open. These guarantees
apply to direct West processing, not wrapper commands, API requests, or other
native VulnScout clients. Coordinate those writers separately, and do not
override `INPUTS_DIR` in a mounted configuration file.

(operation-deadlines)=
## Operation deadlines

`--timeout SECONDS` bounds each finite generation, import, scan, refresh, report,
export, or file-copy operation. The default is 3600 seconds; positive fractional
values are allowed, up to 86400 seconds. Increase it for long scans:

```sh
west vulnscout -d build --perform-scan --timeout 7200
```

Container metadata, lifecycle cleanup, and interface queries have a 30-second
client deadline. Readiness probes have a 5-second deadline per attempt, and
container creation/start allows 300 seconds, including image retrieval.

Direct backend operations also enforce the deadline inside the container.
On expiry, the supervisor terminates the operation's process group, allows up to
5 seconds for graceful exit, then kills remaining children before releasing the
processing lock and cleaning owned inputs. The client allows an additional
35 seconds for that shutdown and container-engine overhead. A timeout is an
execution error, not a vulnerability-policy match, and never causes an SPDX
version downgrade.

The attached web server deliberately has no lifetime timeout. In direct mode,
its preceding processing phase is still bounded. Wrapper `--serve` remains an
interactive session owned by the wrapper; other wrapper invocations have a
client deadline, but West cannot supervise wrapper-managed container jobs.

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

`--dev` is supported only in wrapper mode. The `report` and `export` actions
require direct container mode and reject `--vulnscout-cmd`. The wrapper retains
its own cache, input, concurrency, and interactive-mode behavior.
