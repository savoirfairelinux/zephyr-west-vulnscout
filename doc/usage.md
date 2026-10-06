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

If SPDX files already exist and you only want to import them:

```sh
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d demo/mbedtls_sbom/build \
  --no-generate \
  --project default \
  --variant zephyr_demo \
  --serve
```

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
