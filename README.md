# Nosana FRP collector

Collect the logs and connection details needed to investigate Nosana's **“Node API is detected offline”** and FRP **“router config conflict”** messages. The collector prints recent log excerpts and a plain-language summary for a screenshot, then saves a fuller text report and prints its filename.

This is an independent support tool for the **Docker → Podman** installation layout. It does not require a Nosana admin login.

## Run in one step

Paste this into a Bash terminal **on the affected PC**:

```bash
bash -o pipefail -c 'curl -fsSL https://raw.githubusercontent.com/MachoDrone/nosana-frp-collector/main/start.sh | bash'
```

Or use `wget`:

```bash
bash -o pipefail -c 'wget -qO- https://raw.githubusercontent.com/MachoDrone/nosana-frp-collector/main/start.sh | bash'
```

**No manual download, checkout, or installation is needed.** The launcher automatically fetches the versioned Python collector into a temporary directory, verifies its SHA-256 checksum against the value embedded in the launcher, runs it, and removes the temporary copy. The report stays on your PC. The outer Bash command reports a failure if fetching the launcher fails.

The `main` launcher currently selects **v0.1.1**. To keep using this release's launcher, replace `/main/start.sh` with `/v0.1.1/start.sh` in the command. The checksum checks that the payload matches the launcher; the launcher itself is fetched over HTTPS from this repository.

## Requirements

- Linux with Bash and Python **3.8 or newer**.
- `curl` or `wget` and internet access to GitHub for the launcher and collector.
- Docker installed, its daemon running, and permission to use it from the current terminal.
- An existing outer Docker container named `podman`, or a different name supplied with `--container`.
- The standard rootful Podman storage directory inside that container: `/var/lib/containers/storage/overlay-containers`.

The launcher does not install packages, change permissions, or invoke `sudo`. If Docker reports permission denied, use your normal authorized Docker terminal. It does not require passwordless sudo.

The **outer `podman` container may be running or stopped**. Docker itself must be running. When the outer container is stopped, the collector reads retained files with `docker cp` and marks live checks as unavailable. It does not start the container.

## What you get

The terminal shows recent FRP logs, relevant Nosana API/DNS events, and a summary. The saved report includes:

- Collection time in UTC and the PC's hostname.
- Selected outer-container state, including start/finish times, exit status, and restart count.
- Retained `frpc-api-<node identity>` container names, IDs, and logs, including registration successes and route conflicts.
- Relevant API/DNS events from the matching Nosana node's retained log.
- Current inner-container state where available.
- When the matching node is running and its routing information is verified: DNS lookups and unauthenticated GET checks of the local and public `/` and `/node/info` endpoints, from inside that node's container.

The final line tells you what to share:

```text
Send this file: /your/current/directory/nosana-frp-<hostname>-<UTC timestamp>.txt
```

The report is created in the current directory with permissions `0600` (owner read/write only). It is never uploaded automatically. A screenshot of the final summary is useful for an initial review; the text report provides more context and searchable timestamps.

## Options

Pass options after `bash -s --`. For example, collect retained logs and state without DNS/HTTP probes:

```bash
bash -o pipefail -c 'curl -fsSL https://raw.githubusercontent.com/MachoDrone/nosana-frp-collector/main/start.sh | bash -s -- --logs-only'
```

| Option | Purpose |
| --- | --- |
| `--container NAME` | Select an existing outer Docker container; default: `podman`. |
| `--output-dir PATH` | Choose an existing writable directory for the report; default: the current directory. |
| `--logs-only` | Skip live DNS/HTTP probes. |
| `--version` | Show the collector version. |
| `--help` | Show usage and options. |

For the full help, run:

```bash
bash -o pipefail -c 'curl -fsSL https://raw.githubusercontent.com/MachoDrone/nosana-frp-collector/main/start.sh | bash -s -- --help'
```

## How to interpret the results

| Result | Meaning |
| --- | --- |
| Historical `start proxy success` | FRP accepted the proxy at that log timestamp. It does not establish that the API is reachable now. |
| Historical `router config conflict` | A route-registration collision was reported. Client logs cannot identify the conflicting route's owner or prove that its registration is stale. |
| Current public root responds with the expected identity | The collector reached the expected node through the public API URL at the displayed check time. |
| `/node/info` returns HTTP 200 with a JSON object | That endpoint responded. This does not establish benchmark success or job qualification. |
| Current DNS succeeds | DNS resolved during this collection. An earlier DNS failure remains possible. |
| Live checks skipped | The required running container or verified routing information was unavailable, or `--logs-only` was requested. This is not itself proof of an outage. |

The tool is a collector, not a repair command. It does not clear server routes, rerun benchmarks, start or stop jobs, or restart containers. It cannot read Nosana's FRP server-side logs.

## Collection limits and privacy

Only selected diagnostic fields and retained logs are collected. The tool does not read wallet/key files, dump container environments, obtain signatures, or make authenticated requests. It makes no configuration changes. Live checks produce a few DNS/HTTP requests; `--logs-only` disables those probes.

Reports include public node identities, container IDs, service hostnames, and network addresses. Known sensitive log patterns are redacted, but arbitrary log text cannot be guaranteed free of secrets. **Review the terminal output and report before sharing them.** Do not attach reports or real host fixtures to this public repository.

Deleted containers may no longer have retained records or logs. Alternative storage layouts, rootless Podman, and non-file logging drivers may not be supported. Logs can grow or rotate during collection, so a report is not an atomic snapshot. The collector limits retained FRP log text to the last 16 MiB and filters node events from the last 2 MiB; files exceeding its 256 MiB scan limit may be omitted. Missing or truncated evidence is labeled in the output.

## Development

The collector uses the Python standard library. Run the offline checks from a checkout:

```bash
bash -n start.sh
python3 -m py_compile collector.py
python3 -m unittest discover -s tests -v
```

CI also verifies that the launcher's pinned SHA-256 matches `collector.py`. Tests use synthetic fixtures and do not require a live Nosana host, Docker daemon, or network access.

Licensed under [MIT](LICENSE).
