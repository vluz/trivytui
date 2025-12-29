# Trivy TUI

Terminal UI for [Trivy](https://github.com/aquasecurity/trivy) scanning, written in C with ncurses.      
It guides filesystem or Docker image scans and presents colorized, scrollable results for      
vulnerabilities, secrets, and licenses.

Built as weekend project to scare my sysadmin colleagues. :)     
Utility and convenience might also been my goals but scaring was definitely up there.    

Tested in Rocky Linux 8.10 and Ubuntu 24.04 LTS.     

This was done for my purposes, any feature or enhancement suggestions are welcome.     

## Highlights
- Guided filesystem and image scans with a simple curses UI.
- Settings to toggle secrets/licenses scanning, set severity/ignore filters, configure timeouts and root-skip dirs, and refresh the DB when online.
- Auto-start scan summary with DB status before running, plus rescan last target.
- Main menu footer shows detected Trivy and DB versions.
- Save report output to a file and view the last error log.
- Colorized summary, severity score, and readable detail view.
- Works with older Trivy versions by falling back to supported flags.

## Requirements
- Linux. (Tested in Rocky Linux and Ubuntu.)
- Build deps: `ncurses` and `jansson` development headers.
- Trivy in `PATH` (install manually).
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

# Install (default: /usr/local/bin)
sudo make install

# Alt install (default: /opt/trivytui/bin)
sudo make altinstall

# Run
./trivytui   # Use sudo for access to some filesystems and/or docker
```

Binary builds are provided in Releases.

## Controls
- Main menu: arrows + Enter; `e` exits (includes Rescan last target); shows Trivy/DB versions at bottom.
- Directory browser: Enter opens dir, Space selects path, `b` back, `m` main menu, `e` exit.
- Image picker: arrows + Enter select image, `b` back, `m` main menu, `e` exit (last selection remembered).
- Scan summary: auto-starts after 5s; Enter starts now; `b`/`c` back, `m` menu, `e` exit.
- Spinners: press `c` to cancel scans or DB updates.
- Settings: toggle secrets/licenses scans; set severity threshold, ignore file, timeout, and root-skip dirs; redownload DB (requires internet); view last error.
- Report view: arrows scroll, PgUp/PgDn jump, `s` save report (JSON), `b` back to picker, `m` main menu, `e` exit.

## Notes
- DB update is available from Settings and requires internet connectivity.
- Docker required for image scans; filesystem scans work without Docker.
- License scanning uses Trivy's `--scanners` and `--license-full` flags when available, and falls back for older versions.
- Ignore file uses Trivy's `--ignorefile` format.
- Root skip dirs apply only when scanning `/` and are configurable in Settings.
- Saved reports are raw Trivy JSON output.
- Saved reports append `.json` if missing.
- Default root skip dirs: `/proc,/sys,/run,/dev,/var/lib/docker,/var/lib/containers`.
- Although it allows full filesystem scan, it is slow and probably not useful.

## Manual Trivy Install
If Trivy is not installed, install it manually:
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

## License
License is CC0 1.0 Universal. Please do with this code as you see fit.
If your country/region does not support CC0, consider the code as Public Domain.

---
