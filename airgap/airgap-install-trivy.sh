#!/usr/bin/env bash
# airgap-install-trivy.sh
#
# Installs Trivy + places the offline DB cache.
# Assumes this script and the transferred files are in the same directory.
#
# Looks for:
#   - trivy_*.deb   (preferred on Debian/Ubuntu)
#   - trivy_*.rpm   (preferred on RHEL/Fedora/CentOS)
#     or trivy_*.tar.gz (fallback if you transferred only tarball)
#   - trivy-cache.tgz
#
# Installs:
#   - Trivy (DEB via dpkg, RPM via dnf/yum/rpm, or binary to /usr/local/bin)
#   - DB cache to /var/lib/trivy (default)
#
# Env overrides:
#   TRIVY_CACHE_DIR=/some/path   (default /var/lib/trivy)

set -euo pipefail

log() { printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

need_cmd tar
need_cmd uname
need_cmd date

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="${TRIVY_CACHE_DIR:-/var/lib/trivy}"

if [[ "$(id -u)" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    die "This script must run as root (or have sudo installed)."
  fi
else
  SUDO=""
fi

cd "$SCRIPT_DIR"

# Optional: verify offline checksums if present
if [[ -f trivy-offline-sha256sums.txt ]] && command -v sha256sum >/dev/null 2>&1; then
  log "Verifying transferred files using trivy-offline-sha256sums.txt ..."
  sha256sum -c trivy-offline-sha256sums.txt
fi

# Install Trivy
RPM_FILE=""
DEB_FILE=""
TAR_FILE=""

# Pick newest matching file if multiple exist
DEB_FILE="$(ls -1 trivy_*_Linux-*.deb 2>/dev/null | sort -V | tail -n 1 || true)"
RPM_FILE="$(ls -1 trivy_*_Linux-*.rpm 2>/dev/null | sort -V | tail -n 1 || true)"
TAR_FILE="$(ls -1 trivy_*_Linux-*.tar.gz 2>/dev/null | sort -V | tail -n 1 || true)"

if [[ -n "$DEB_FILE" ]] && command -v dpkg >/dev/null 2>&1; then
  log "Installing Trivy from DEB: $DEB_FILE"
  $SUDO dpkg -i "./$DEB_FILE"
elif [[ -n "$RPM_FILE" ]]; then
  log "Installing Trivy from RPM: $RPM_FILE"
  if command -v dnf >/dev/null 2>&1; then
    $SUDO dnf -y install "./$RPM_FILE"
  elif command -v yum >/dev/null 2>&1; then
    $SUDO yum -y install "./$RPM_FILE"
  elif command -v rpm >/dev/null 2>&1; then
    $SUDO rpm -Uvh "./$RPM_FILE"
  else
    die "No package manager found (dnf/yum/rpm)."
  fi
elif [[ -n "$TAR_FILE" ]]; then
  log "RPM not found; installing Trivy from tarball: $TAR_FILE"
  WORKDIR="$(mktemp -d)"
  trap 'rm -rf "$WORKDIR"' EXIT
  tar -xzf "./$TAR_FILE" -C "$WORKDIR"
  [[ -x "$WORKDIR/trivy" ]] || die "trivy binary not found in tarball."
  $SUDO install -m 0755 "$WORKDIR/trivy" /usr/local/bin/trivy
else
  die "No Trivy DEB/RPM or tarball found in $SCRIPT_DIR (expected trivy_*_Linux-*.deb, trivy_*_Linux-*.rpm, or trivy_*_Linux-*.tar.gz)."
fi

TRIVY_BIN="$(command -v trivy || true)"
[[ -n "$TRIVY_BIN" ]] || die "Trivy is not on PATH after installation."

log "Trivy installed: $("$TRIVY_BIN" --version | head -n 1 || true)"

# Install offline DB cache
[[ -f trivy-cache.tgz ]] || die "Missing trivy-cache.tgz in $SCRIPT_DIR"

log "Installing Trivy cache to: $CACHE_DIR"
$SUDO mkdir -p "$CACHE_DIR"
$SUDO tar -xzf trivy-cache.tgz -C "$CACHE_DIR"

# Ensure expected dirs exist (java-db may be absent if you skipped it)
if [[ ! -d "$CACHE_DIR/db" ]]; then
  die "Expected '$CACHE_DIR/db' after extracting trivy-cache.tgz, but it was not found."
fi

# Basic permissions: readable by all, writable by root.
$SUDO chmod 0755 "$CACHE_DIR"
$SUDO chmod 0755 "$CACHE_DIR/db" || true
$SUDO find "$CACHE_DIR/db" -type f -exec chmod 0644 {} \; || true

if [[ -d "$CACHE_DIR/java-db" ]]; then
  $SUDO chmod 0755 "$CACHE_DIR/java-db" || true
  $SUDO find "$CACHE_DIR/java-db" -type f -exec chmod 0644 {} \; || true
fi

log "Offline DB cache installed."
log "Example offline scan usage:"
log "  trivy fs --cache-dir $CACHE_DIR --skip-db-update --skip-java-db-update --skip-check-update --offline-scan /path/to/scan"
log "Done."
