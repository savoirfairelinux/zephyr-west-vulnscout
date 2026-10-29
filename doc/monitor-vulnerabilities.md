# Monitor Vulnerabilities

## Evaluate a match condition

Use VulnScout's `match-condition` command to fail a CI job when a
vulnerability satisfies your policy:

```sh
west vulnscout match-condition 'cvss >= 9.0 and (pending or affected)' \
  -d demo/mbedtls_sbom/build \
  --project zephyr_demo --variant mbedtls_native_sim
```

The condition is evaluated against vulnerability data stored in VulnScout for
the selected variant. West does not generate or stage an SBOM for this command.
It does not request vulnerability scanners or automatically refresh provider
metadata.

To discover vulnerabilities before evaluation, run `west vulnscout scan` with
the same build directory, project, and variant first. See
[Vulnerability Scanning](vulnerability-scanning.md).

Matching vulnerability IDs are printed in the command output.

## Conditions and tokens

Quote the entire expression so the shell does not interpret parentheses,
spaces, or comparison operators. Use `and`, `or`, `not`, parentheses, and
`>`, `>=`, `<`, `<=`, `==`, or `!=`.

Common tokens are:

| Token | Meaning |
| --- | --- |
| `id` | Vulnerability identifier, such as `CVE-2021-44228`. |
| `cvss`, `cvss_min` | Maximum and minimum CVSS scores, generally between 0 and 10. |
| `epss` | EPSS score between 0 and 1; `30%` is equivalent to `0.30`. |
| `known_exploitable` | The EUVD known-exploited flag. |
| `pending` | Awaiting review / under investigation. |
| `affected` | Assessed as affecting the product / exploitable. |
| `fixed` | Assessed as fixed / resolved. |
| `ignored` | Assessed as not affected / false positive. |
| `effort`, `effort_min`, `effort_max` | Likely, optimistic, and pessimistic fix effort in seconds. `effort` is false when unset. |

Status tokens use assessments within the evaluated scope. A vulnerability
without an assessment is pending. Boolean tokens can be used directly, such as
`pending` or `not fixed`.

Missing CVSS or EPSS values evaluate as false (numerically zero), not as proof
that a vulnerability is low risk.

Example policies:

| Policy | Condition |
| --- | --- |
| Critical vulnerabilities | `cvss >= 9.0` |
| High severity and high exploitation probability | `cvss >= 7.0 and epss >= 30%` |
| Known exploited and unresolved | `known_exploitable and (pending or affected)` |
| High severity, not fixed or ignored | `cvss >= 7.0 and not fixed and not ignored` |
| A specific vulnerability | `id == CVE-2021-44228` |
| Affected vulnerabilities without an effort estimate | `affected and not effort` |
| Known fix effort under one hour | `affected and effort and effort < 3600` |

Identifiers on the right side of `==` or `!=` are literal strings; do not add
inner quotes around the CVE ID. Unknown tokens elsewhere are errors.

For the complete language and token reference, see VulnScout's
[Writing Match Conditions](https://vulnscout.readthedocs.io/en/latest/ci_conditions.html).

## Refresh data before evaluation

To refresh all stored vulnerability metadata in the selected variant before
evaluation, first run a separate refresh:

```sh
west vulnscout refresh -d demo/mbedtls_sbom/build \
  --project zephyr_demo --variant mbedtls_native_sim
```

Then run the condition command above. For a full workflow, run `add`, `scan`,
`refresh`, and `match-condition` as separate commands in that order.

Condition evaluation uses VulnScout's native processing path, which can reread
files registered with the latest scan. Direct mode isolates pending input files
from other invocations. Wrapper mode retains VulnScout's own input handling.

Scores and exploitation flags can be missing or stale until their providers
are refreshed. See [Refresh Vulnerability Data](vulnerability-data.md).

## Project, variant, and cache scope

Keep the same project, variant, and cache as the original import. Add
`--vulnscout-data-dir /path/to/existing/cache` when the container uses a
non-default cache.

The extension always passes both project and variant; omitted options become
`default/default`. In particular, `--project NAME` without `--variant` selects
that project's `default` variant, not all its variants. Run the command
separately for each variant when monitoring multiple builds.

## Exit status and CI integration

| Code | Meaning |
| --- | --- |
| `0` | Processing succeeded and no vulnerability matched. |
| `1` | Execution error, such as an invalid condition or processing failure. |
| `2` | At least one vulnerability matched the condition. |

These statuses are preserved in direct container and wrapper modes. A condition
match is distinct from a tool error. To handle them separately in a shell,
including when `set -e` is enabled:

```sh
status=0
west vulnscout match-condition 'cvss >= 9.0' \
  -d demo/mbedtls_sbom/build \
  --project zephyr_demo --variant mbedtls_native_sim || status=$?

case "$status" in
  0) echo "Policy passed" ;;
  2) echo "Vulnerability policy triggered" ;;
  *) echo "VulnScout execution failed" >&2 ;;
esac
exit "$status"
```

`match-condition` is a separate command from `serve`. It can be combined with
`--stop-after-run`; cleanup runs after a completed evaluation even when the
condition matches, and the command still exits with `2`.
