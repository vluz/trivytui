# Trivy TUI

Terminal UI for [Trivy](https://github.com/aquasecurity/trivy) scanning, written in C with ncurses.      
It guides filesystem or Docker image scans and presents colorized, scrollable results for      
vulnerabilities, secrets, and licenses.

Built as over-the-holidays project to scare my sysadmin colleagues. :)      
Utility and convenience might also been my goals but scaring was definitely up there.

**Version 0.9.3** - Reports now display descriptions correctly. Fixed versions troughout.

Version 0.9.2 - Added airgapped scripts

Version 0.9.1 - Security hardened with comprehensive input validation, buffer overflow protection, and improved code quality.

Version 0.9.0 - Initial release build

Tested in Rocky Linux 8.10, Ubuntu 24.04 LTS and Debian 13.2.

This was done for my purposes, any feature or enhancement suggestions are welcome.

## Highlights
- **Scan History View**: Quick overview of recent scans with security scores and severity breakdowns.
- Guided filesystem and image scans with a simple curses UI.
- **Search & Filter**: Real-time search through results (press `/`) with case-insensitive filtering.
- **Multiple Export Formats**: Export to JSON, HTML (with embedded CSS), or Markdown (press `x`).
- **Automatic History Tracking**: Records last 10 scans with scores and vulnerability counts.
- Settings to toggle secrets/licenses scanning, set severity/ignore filters, configure timeouts and root-skip dirs, and refresh the DB when online.
- Auto-start scan summary with DB status before running, plus rescan last target.
- Main menu footer shows detected Trivy and DB versions.
- Save report output to a file and view the last error log.
- Colorized summary, severity score, and readable detail view.
- Works with older Trivy versions by falling back to supported flags.

## Security Enhancements (v0.9.1)
- **Input Validation**: Command injection prevention with strict input sanitization
- **Path Traversal Protection**: Directory listing validates against malicious paths
- **Buffer Overflow Prevention**: Size checks before string operations and proper null termination
- **Integer Overflow Checks**: Safe buffer allocation with overflow detection
- **Race Condition Fixes**: Proper file descriptor handling in subprocess communication
- **Reduced Global State**: Application context structure for better code organization
- **Comprehensive Documentation**: Doxygen-style comments throughout codebase

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

# Run unit tests
make test

# Install (default: /usr/local/bin)
sudo make install

# Alt install (default: /opt/trivytui/bin)
sudo make altinstall

# Run
./trivytui   # Use sudo for access to some filesystems and/or docker
```

Binary builds are provided in Releases.

## Version Management

The project uses automated version detection:

1. **Git tags** (preferred): Version is automatically extracted from git tags
2. **Manual override**: Use `VERSION=x.x.x` for custom versions
3. **Hardcoded fallback**: Uses version 0.9.3 if no tags exist

```bash
# Check detected version
make show-version

# Build with auto-detected version (from git tags or fallback)
make

# Build with specific version
make VERSION=1.0.0

# Create a new release
git tag -a v0.9.4 -m "Release v0.9.4"
git push origin v0.9.4
make  # Automatically uses 0.9.4

# Check binary version
./trivytui --version
```

## Building Packages

To create RPM and DEB packages (requires Rocky Linux 8.10 or compatible):

```bash
# Build with auto-detected version
sudo make packages

# Build with specific version
sudo make packages VERSION=0.9.4
```

  Packages will be created in build/ directory:
  - trivytui-0.9.3-1.el8.x86_64.rpm
  - trivytui_0.9.3-1_amd64.deb
  - trivytui-0.9.3.tar.gz
  - SHA256SUMS

The packaging script uses:
- `rpmbuild` for RPM creation
- Manual `ar` + `tar` for DEB creation (no dpkg-deb required)
- Comprehensive checksums for verification

## Testing
The project now includes unit tests covering:
- Input validation (command injection prevention)
- Path traversal detection
- Buffer overflow prevention logic
- Integer overflow checks
- Severity score calculation
- Basic data structure operations

Run tests with:
```bash
make test
# or
make check
```

## Controls

### Main Menu
- Arrows + Enter to navigate; `e` exits
- Shows Trivy/DB versions at bottom
- Options: Filesystem scan, Image scan, Rescan last target, History, Settings, Exit
- History menu item shows " - (empty)" when no scans have been performed

### History (NEW!)
- Shows overview of most recent scan with security score (0-100)
- Color-coded severity breakdown with bar charts
- List of up to 5 recent scans with scores
- Security score interpretation:
  - 90-100: Excellent (green/cyan)
  - 70-89: Good (yellow)
  - 50-69: Fair (magenta)
  - 0-49: Poor (red)
- Press any key to return to main menu

### Directory Browser
- Enter opens directory
- Space selects current path
- `b` back, `m` main menu, `e` exit

### Image Picker
- Arrows + Enter select image
- Last selection remembered
- `b` back, `m` main menu, `e` exit

### Scan Summary
- Auto-starts after 5 seconds
- Enter to start immediately
- `b`/`c` back, `m` menu, `e` exit

### Report Viewer (NEW!)
**Navigation:**
- Arrows/`j`/`k` scroll line by line
- PgUp/PgDn jump by page
- `n` next occurrence, `N` previous

**Search & Filter:**
- `/` open search prompt
- Enter search term (case-insensitive)
- `c` clear current filter
- Status line shows `Filter: 'term' (X/Y lines)`

**Export:**
- `x` open export menu
- Choose format: JSON, HTML, or Markdown
- HTML: Styled report with embedded CSS (email-friendly)
- Markdown: GitHub/GitLab compatible with emoji badges
- `s` legacy JSON save (kept for compatibility)

**Other:**
- `b` back to picker
- `m` return to main menu
- `e` exit application

### Settings Menu
- Toggle secrets/licenses scanning
- Set severity threshold (All/Low+/Medium+/High+/Critical)
- Configure ignore file, timeout, root-skip dirs
- Redownload DB (requires internet)
- View last error log

## Notes
- History stores last 10 scans in memory (not persisted between sessions).
- Security scores use exponential decay formula: `100 * exp(-0.0025 * weighted_count)`.
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

## Airgapped Install (Offline)
Two helper scripts are provided under `airgap/` to stage Trivy and its DB on a connected machine and install them on an airgapped host.

**1) On a machine with internet:**
```bash
# Downloads latest Trivy release assets + DB cache into ./airgap
bash airgap/stage-download-trivy.sh
```
This produces `trivy-cache.tgz` plus platform packages (RPM/DEB) and a tarball.

**2) Transfer files to the airgapped machine:**
- `trivy_*.deb` (Ubuntu/Debian) or `trivy_*.rpm` (RHEL/Fedora)
- `trivy-cache.tgz`
- Optional: `trivy-offline-manifest.txt` and `trivy-offline-sha256sums.txt`

**3) On the airgapped machine:**
```bash
sudo bash airgap/airgap-install-trivy.sh
```
By default, the cache is installed under `/var/lib/trivy`. Set `TRIVY_CACHE_DIR` to override.

## Development

### Code Quality
The codebase follows these principles:
- **Clear Documentation**: Doxygen-style comments for all major functions and structures
- **Named Constants**: All magic numbers replaced with descriptive defines
- **Error Handling**: Consistent error checking and reporting
- **Memory Safety**: Proper allocation checks and cleanup
- **Security First**: All inputs validated, all buffers checked

### Project Structure
- `main.c` - Main application with UI and scanning logic (~2900 lines)
- `test_trivytui.c` - Unit tests for core functionality
- `Makefile` - Build configuration with test support

### Contributing
Issues and pull requests welcome! When contributing:
- Follow the existing code style (K&R-ish with documentation)
- Add tests for new functionality
- Update README for user-facing changes
- Run `make test` before submitting

## License
License is CC0 1.0 Universal. Please do with this code as you see fit.
If your country/region does not support CC0, consider the code as Public Domain.

## Export Format Examples

### HTML Export
Creates a self-contained HTML file with:
- Dark theme styling (VS Code inspired)
- Color-coded severity levels
- Responsive layout
- Embedded CSS (no external dependencies)
- Perfect for email attachments or offline viewing

### Markdown Export
GitHub/GitLab compatible format with:
- Emoji badges for severity levels (🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM, 🔵 LOW)
- Proper heading hierarchy
- Easy to paste into issues/PRs
- Readable in any markdown viewer

### Search Examples
```
Search for specific CVE:     /CVE-2024-1234
Filter by package name:       /openssl
Show only CRITICAL findings:  /CRITICAL
Find secrets:                 /secret
Search in descriptions:       /buffer overflow
```

## Changelog

### Version 0.9.3 (2026)
- Fixed reporting errors if CVE text contained a script html tag.

### Version 0.9.2 (2026)
- Added airgap helpers
- Fixed small bugs
- Fixed offline functionality

### Version 0.9.1 (2026)
- Airgap staging and installation scripts added
- History view with scan tracking and security scores
- Automatic tracking of last 10 scans with statistics
- Color-coded severity bar charts in history view
- Dynamic menu labels showing history status
- Search & filter in report viewer (press `/`)
- Export to HTML and Markdown formats (press `x`)
- Interactive export format menu
- Real-time filter status display
- **Security**: Input validation, buffer overflow fixes, path traversal protection
- **Quality**: Reduced global state, comprehensive documentation, unit tests
- **Refactoring**: Named constants, improved error handling
- **Testing**: Unit test framework with coverage of security-critical code

### Version 0.9.0 (2025)
- Initial release with filesystem and image scanning
- Interactive TUI with ncurses
- Trivy version detection and fallback support

---
