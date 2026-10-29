# Interactive Mode (Web UI)

## Serve stored results

After importing with `west vulnscout add`, serve the web interface:

```sh
west vulnscout serve -d demo/mbedtls_sbom/build
```

Open http://localhost:7275/ and select project `zephyr_demo`, variant
`mbedtls_native_sim`.

`serve` does not generate or import an SBOM, scan, or refresh vulnerability
metadata. The interface displays every project and variant in the selected
cache. No project or variant options are needed for serving.

The processing lock is not held while serving, allowing later West imports,
scans, and refreshes while the interface stays open. Wrapper mode retains
VulnScout's native startup behavior.
See {ref}`input-isolation-and-concurrent-processing`.

(custom-port-and-browser-url)=
## Custom port and browser URL

Direct container mode uses the same configuration variable names as
`meta-vulnscout`, forwarding their values to VulnScout's native Flask settings:

| Variable | Purpose | Default |
| --- | --- | --- |
| `VULNSCOUT_ENV_FLASK_RUN_PORT` | Flask's container port and the host port published for a new container. | `7275` |
| `VULNSCOUT_ENV_FLASK_RUN_HOST` | The address Flask binds to **inside the container**. | `0.0.0.0` |

Set these variables in the shell before invoking West. The native
`FLASK_RUN_PORT` and `FLASK_RUN_HOST` environment variables are also accepted
as fallbacks; the `VULNSCOUT_ENV_*` variables take precedence.

For example, serve the interface on port 8080 using a separate container name:

```sh
export VULNSCOUT_ENV_FLASK_RUN_HOST=0.0.0.0
export VULNSCOUT_ENV_FLASK_RUN_PORT=8080

west vulnscout serve -d demo/mbedtls_sbom/build \
  --container-name vulnscout-8080
```

Open http://localhost:8080/. Keep the same environment variables, container name,
and cache settings in subsequent commands. A new container publishes
`8080:8080`. Direct `serve` forwards both variables to the entrypoint.

An existing container retains its published ports; changing environment
variables cannot change those mappings. Check them with:

```sh
podman port vulnscout-8080
```

If the required port is not published, use a new container name or coordinate
stopping and recreating the old container with the same persistent cache.
The extension does not remove or recreate a shared container automatically.
Containers with a mounted VulnScout configuration file also need matching
`FLASK_RUN_HOST`/`FLASK_RUN_PORT` settings there, since the entrypoint loads
that file.

`FLASK_RUN_HOST` is not the browser's hostname. Leave it at `0.0.0.0` for normal
container networking; `127.0.0.1` binds only to the container's loopback
interface and is not reachable through ordinary published ports.
To use a URL such as `http://vulnscout.example.com:8080/`, configure that DNS name
to resolve to the machine running the container. HTTPS requires a TLS reverse
proxy; these settings do not configure a public hostname or TLS.

These examples use direct container mode. With `--vulnscout-cmd`, the wrapper
owns its configuration and port publishing. The West extension does not remap
wrapper-managed ports; the current VulnScout wrapper publishes `7275:7275`.

## Reuse a running web interface

If the container is already serving the interface, run `add`, `scan`, and
`refresh` separately. Do not start a second web server in the same
container. Report generation also reuses the container without restarting the
web server.

## Stop serving

In direct container mode, pressing Ctrl+C while `serve` is running stops the
VulnScout container before exiting, including its other services. Do not stop
a shared container without coordinating with its other users.

`serve` cannot be combined with `--stop-after-run`. See
[Container Lifecycle and Configuration](container-configuration.md) for explicit
stop commands and wrapper mode.

Run a separate
[Monitor Vulnerabilities](monitor-vulnerabilities.md) command for CI policy
evaluation.
