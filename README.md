# Trivy TUI

Terminal UI for [Trivy](https://github.com/aquasecurity/trivy) scanning, written in C with ncurses.
It guides filesystem or Docker image scans and presents colorized, scrollable results for
vulnerabilities, secrets, and licenses.

## Highlights
- Guided filesystem and image scans with a simple curses UI.
- Auto-install Trivy if missing (best-effort) and refresh the DB.
- Colorized summary, severity score, and readable detail view.
- Works with older Trivy versions by falling back to supported flags.

## Requirements
- Linux.
- Build deps: `ncurses` and `jansson` development headers.
- Trivy in `PATH` (auto-installed if missing).
- Docker optional (only needed for image scans).

## Install Dependencies
```bash
# Rocky/RHEL/CentOS
sudo dnf -y groupinstall -y "Development Tools"
sudo dnf -y install -y ncurses-devel jansson-devel

# Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y build-essential libncurses-dev libjansson-dev
```

## Build & Run
```bash
# Build
gcc -std=c11 -Wall -Wextra -pedantic main.c -lncurses -ljansson -lm -o trivytui

# Or use the Makefile
make

# Run
./trivytui   # Use sudo for access to some filesystems
```

## Controls
- Main menu: arrows + Enter; `e` exits.
- Directory browser: Enter opens dir, Space selects path, `b` back, `m` main menu, `e` exit.
- Image picker: arrows + Enter select image, `b` back, `m` main menu, `e` exit (last selection remembered).
- Report view: arrows scroll, PgUp/PgDn jump, `b` back to picker, `m` main menu, `e` exit.

## Notes
- Trivy install uses `curl` via the official installer. Prefers `/usr/local/bin` with sudo; falls back to `$HOME/.local/bin`.
- DB update is best-effort; if unsupported flags are hit, scans still run and Trivy will fetch as needed.
- Docker required for image scans; filesystem scans work without Docker.
- License scanning uses Trivy's `--scanners` and `--license-full` flags when available, and falls back for older versions.

## Manual Trivy Install
If automatic install fails, install Trivy manually:
```bash
# Preferred (needs curl + sudo)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sudo sh -s -- -b /usr/local/bin

# Without sudo, install into $HOME/.local/bin
mkdir -p ~/.local/bin
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sh -s -- -b ~/.local/bin
echo 'export PATH=$HOME/.local/bin:$PATH' >> ~/.bashrc
source ~/.bashrc

# Verify
trivy --version
trivy image --download-db-only --no-progress
```

---
