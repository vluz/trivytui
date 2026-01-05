#!/usr/bin/env bash
# stage-download-trivy.sh
#
# Downloads the *latest* Trivy release (RPM + DEB + tarball + checksums) and
# pre-downloads Trivy vulnerability DB + Java DB into a tarball for offline use.
#
# Output files (in the same directory as this script):
#   - trivy_<VER>_<...>.rpm
#   - trivy_<VER>_<...>.deb
#   - trivy_<VER>_<...>.tar.gz
#   - trivy_<VER>_checksums.txt
#   - trivy-cache.tgz          (contains db/ and java-db/ cache dirs)
#   - trivy-offline-manifest.txt
#   - trivy-offline-sha256sums.txt
#
# Env overrides:
#   OUT_DIR=/path/to/output
#   SKIP_JAVA_DB=1

set -euo pipefail

log() { printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

need_cmd curl
need_cmd python3
need_cmd sha256sum
need_cmd tar
need_cmd uname
need_cmd mktemp
need_cmd date

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${OUT_DIR:-$SCRIPT_DIR}"
mkdir -p "$OUT_DIR"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) WANT_TOKEN="Linux-64bit" ;;
  aarch64|arm64) WANT_TOKEN="Linux-ARM64" ;;
  *)
    die "Unsupported arch '$ARCH'. Supported: x86_64/amd64, aarch64/arm64"
    ;;
esac

WORKDIR="$(mktemp -d)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

log "Detecting latest Trivy release via GitHub API..."
RELEASE_JSON="$WORKDIR/release.json"
curl -fsSL \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/aquasecurity/trivy/releases/latest" \
  -o "$RELEASE_JSON"

# Extract version + asset names (RPM + tar.gz + checksums) matching our arch.
read -r VER RPM_NAME DEB_NAME TAR_NAME SUMS_NAME < <(
python3 - "$WANT_TOKEN" "$RELEASE_JSON" <<'PY'
import json, sys
want = sys.argv[1]
path = sys.argv[2]
data = json.load(open(path, "r", encoding="utf-8"))
ver = data["tag_name"].lstrip("v")
assets = [a["name"] for a in data.get("assets", [])]

def pick(ext: str, must_contain: str):
    for n in assets:
        if n.startswith("trivy_") and must_contain in n and n.endswith(ext):
            return n
    return ""

rpm = pick(".rpm", want)
deb = pick(".deb", want)
tar = pick(".tar.gz", want)
sums = next((n for n in assets if n.endswith("_checksums.txt")), "")

print(ver, rpm, deb, tar, sums)
PY
)

[[ -n "${VER:-}" ]] || die "Failed to determine latest version."
[[ -n "${RPM_NAME:-}" ]] || die "Could not find RPM asset for token '$WANT_TOKEN'."
[[ -n "${DEB_NAME:-}" ]] || die "Could not find DEB asset for token '$WANT_TOKEN'."
[[ -n "${TAR_NAME:-}" ]] || die "Could not find tar.gz asset for token '$WANT_TOKEN'."
[[ -n "${SUMS_NAME:-}" ]] || die "Could not find checksums asset."

BASE_URL="https://github.com/aquasecurity/trivy/releases/download/v${VER}"

log "Latest version: v${VER} (arch token: ${WANT_TOKEN})"
log "Downloading release assets into: $OUT_DIR"

dl() {
  local name="$1"
  local url="${BASE_URL}/${name}"
  log "  - $name"
  curl -fL --retry 5 --retry-delay 2 --retry-connrefused \
    -o "${OUT_DIR}/${name}" \
    "$url"
}

dl "$RPM_NAME"
dl "$DEB_NAME"
dl "$TAR_NAME"
dl "$SUMS_NAME"

log "Verifying downloaded files against published checksums..."
(
  cd "$OUT_DIR"
  sha256sum -c "$SUMS_NAME" --ignore-missing
)

# Extract Trivy from tar.gz to run "download db only"
BIN_DIR="$WORKDIR/trivybin"
mkdir -p "$BIN_DIR"
tar -xzf "${OUT_DIR}/${TAR_NAME}" -C "$BIN_DIR"
TRIVY_BIN="$BIN_DIR/trivy"
[[ -x "$TRIVY_BIN" ]] || die "Trivy binary not found after extracting ${TAR_NAME}"

CACHE_DIR="$WORKDIR/cache"
mkdir -p "$CACHE_DIR"

log "Downloading vulnerability DB into temporary cache..."
"$TRIVY_BIN" image --cache-dir "$CACHE_DIR" --download-db-only

if [[ "${SKIP_JAVA_DB:-0}" != "1" ]]; then
  log "Downloading Java DB into temporary cache..."
  "$TRIVY_BIN" image --cache-dir "$CACHE_DIR" --download-java-db-only
else
  log "Skipping Java DB download (SKIP_JAVA_DB=1)"
fi

# Package cache dirs for offline transfer
log "Packaging cache into ${OUT_DIR}/trivy-cache.tgz"
(
  cd "$CACHE_DIR"
  if [[ -d db && -d java-db ]]; then
    tar -czf "${OUT_DIR}/trivy-cache.tgz" db java-db
  elif [[ -d db ]]; then
    tar -czf "${OUT_DIR}/trivy-cache.tgz" db
  else
    die "Expected '$CACHE_DIR/db' was not created."
  fi
)

# Build a small manifest (includes DB metadata if present)
MANIFEST="${OUT_DIR}/trivy-offline-manifest.txt"
log "Writing manifest: $MANIFEST"
python3 - "$VER" "$ARCH" "$OUT_DIR" "$MANIFEST" <<'PY'
import json, os, sys, datetime
ver, arch, out_dir, manifest = sys.argv[1:5]
ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

# We packaged cache dirs in tarball; also attempt to read metadata from temp extraction if present in OUT_DIR
# (Not extracting here; just record what we know.)
lines = []
lines.append(f"created_utc={ts}")
lines.append(f"trivy_version=v{ver}")
lines.append(f"staging_arch={arch}")
lines.append("files:")
for fn in sorted(os.listdir(out_dir)):
    if fn.startswith("trivy_") or fn in ("trivy-cache.tgz", "trivy-offline-sha256sums.txt", "trivy-offline-manifest.txt"):
        p = os.path.join(out_dir, fn)
        if os.path.isfile(p):
            lines.append(f"  - {fn}")

with open(manifest, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")
PY

# Create a simple checksum file for what we produced (for offline integrity checks)
SUMOUT="${OUT_DIR}/trivy-offline-sha256sums.txt"
log "Writing sha256 sums: $SUMOUT"
(
  cd "$OUT_DIR"
  # Include the big artifacts + our outputs
  sha256sum "$RPM_NAME" "$DEB_NAME" "$TAR_NAME" "$SUMS_NAME" trivy-cache.tgz trivy-offline-manifest.txt > "$SUMOUT"
)

log "Done."
log "Transfer these to the air-gapped machine (same directory as airgap-install-trivy.sh):"
log "  - ${RPM_NAME}"
log "  - ${DEB_NAME}"
log "  - trivy-cache.tgz"
log "  - trivy-offline-manifest.txt (optional)"
log "  - trivy-offline-sha256sums.txt (optional)"
