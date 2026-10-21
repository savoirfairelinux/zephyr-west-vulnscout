# Writing Report Templates

## Create a custom template

Reports use Jinja2 templates. For example, save this as `my-report.adoc`:

```jinja
= Custom Zephyr Report
Generated: {{ export_date }}

== Components
{% for package in packages.values() %}
* {{ package.name | escape_adoc }} - {{ package.version | escape_adoc }}
{% endfor %}

== Vulnerabilities
{% for vuln in unfiltered_vulnerabilities.values() %}
* {{ vuln.id }}: {{ vuln.description | escape_adoc }}
{% endfor %}
```

`unfiltered_vulnerabilities` contains all vulnerabilities in the selected
project/variant scope. `vulnerabilities` contains only those retained by the
report's assessment/date/EPSS filtering.

See VulnScout's
[Writing Report Templates](https://vulnscout.readthedocs.io/en/latest/templates.html)
for the full template variables, filters, and helpers.

## Install and render a template

Install the custom template in the running container's persistent directory:

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

The generated report is `reports/my-report.adoc.html`. `--template` accepts an
installed filename, not a host path. See
[Report Generation](reports.md) for formats and output options.

## Add images and logos

Install assets in the persistent template asset directory:

```sh
podman exec vulnscout mkdir -p /cache/vulnscout/templates/assets
podman cp logo.png vulnscout:/cache/vulnscout/templates/assets/logo.png
```

Reference an image in your AsciiDoc template with:

```jinja
{{ embed_image("logo.png", width=150, alt="Company logo") }}
```

Use a bare filename, not a path. `embed_image` embeds the image data so the
report does not depend on the original host file. Supported extensions are
`png`, `jpg`, `jpeg`, `gif`, `svg`, and `webp`.

Missing assets render as empty content; `find_asset("logo.png")` can check
availability in a template. Templates and assets stored under
`/cache/vulnscout` persist across container replacement when the same host
cache is reused.
