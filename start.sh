#!/usr/bin/env bash
# Download and run the pinned, verified collector without installing it.

COLLECTOR_REF='v0.1.1'
COLLECTOR_SHA256='914e47c31bc807f6ad4a167aa35cf3768b661403b44a73c57dbbbb539a1bfa40'

main() (
  set -euo pipefail
  umask 077

  local collector_url="https://raw.githubusercontent.com/MachoDrone/nosana-frp-collector/${COLLECTOR_REF}/collector.py"
  local collector_tmp collector_script collector_status

  if ! command -v python3 >/dev/null 2>&1; then
    printf 'Error: Python 3.8 or newer is required; nothing was installed.\n' >&2
    return 1
  fi
  if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)'; then
    printf 'Error: Python 3.8 or newer is required; nothing was installed.\n' >&2
    return 1
  fi
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    printf 'Error: curl or wget is required to download the collector.\n' >&2
    return 1
  fi

  collector_tmp=$(mktemp -d "${TMPDIR:-/tmp}/nosana-frp.XXXXXXXX")
  trap 'rm -rf -- "$collector_tmp"' EXIT
  collector_script="$collector_tmp/collector.py"

  if command -v curl >/dev/null 2>&1; then
    if curl --fail --silent --show-error --location \
      --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --connect-timeout 10 --max-time 90 --retry 2 --retry-delay 1 \
      --output "$collector_script" "$collector_url"; then
      :
    else
      collector_status=$?
      printf 'Error: collector download failed; nothing was executed.\n' >&2
      return "$collector_status"
    fi
  else
    if wget --https-only --timeout=30 --tries=3 --quiet \
      --output-document="$collector_script" "$collector_url"; then
      :
    else
      collector_status=$?
      printf 'Error: collector download failed; nothing was executed.\n' >&2
      return "$collector_status"
    fi
  fi

  python3 - "$collector_script" "$COLLECTOR_SHA256" <<'PY'
import hashlib
import pathlib
import sys

try:
    actual = hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()
except OSError as exc:
    print("Error: cannot read downloaded collector: %s" % exc, file=sys.stderr)
    sys.exit(1)
if actual != sys.argv[2]:
    print("Error: collector SHA-256 verification failed; nothing was executed.",
          file=sys.stderr)
    sys.exit(1)
PY

  # Keep the caller's working directory, arguments, output and exit status.
  python3 "$collector_script" "$@"
)

main "$@"
