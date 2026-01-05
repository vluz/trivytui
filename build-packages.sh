#!/bin/bash
#
# build-packages.sh - Build RPM and DEB packages for trivytui
#
# This script creates distribution packages for trivytui on Rocky Linux 8.10.
# It builds both RPM (for RHEL/Rocky/CentOS) and DEB (for Debian/Ubuntu) packages.
#
# DEB Package Creation:
#   Uses manual construction with tar and ar instead of dpkg-deb (not available
#   on Rocky Linux). Creates proper Debian package structure with control file,
#   data archive, and debian-binary version marker.
#
# Package Contents:
#   - Binary: /usr/bin/trivytui
#   - Documentation: /usr/share/doc/trivytui/README.md
#   - Checksums: SHA256SUMS file for verification
#   - Source tarball: Full source code archive
#
# Usage: sudo ./build-packages.sh [version]
#        or: sudo make packages
#
# Requirements:
# - Rocky Linux 8.10 (or compatible RHEL/CentOS 8)
# - Root or sudo access
# - Internet connection for package installation
# - Tools: rpm-build, Development Tools, ar (from binutils)
#
# Output Directory:
#   All packages are created in: build/
#   - trivytui-VERSION-RELEASE.ARCH.rpm
#   - trivytui_VERSION-RELEASE_amd64.deb
#   - trivytui-VERSION.tar.gz
#   - SHA256SUMS

set -e  # Exit on error
set -u  # Exit on undefined variable

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Package information
PKG_NAME="trivytui"
PKG_VERSION="${1:-0.0.0}"
PKG_RELEASE="1"
PKG_ARCH="x86_64"
PKG_SUMMARY="Terminal UI for Trivy security scanner"
PKG_DESCRIPTION="Interactive ncurses-based terminal interface for the Trivy vulnerability scanner. \
Supports filesystem and Docker image scanning with colorized output, search/filter, \
export to multiple formats, and scan history tracking."
PKG_LICENSE="CC0-1.0"
PKG_URL="https://github.com/your-repo/trivytui"
MAINTAINER="Your Name <your.email@example.com>"

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_ROOT="${SCRIPT_DIR}/build"
RPM_BUILD="${BUILD_ROOT}/rpmbuild"
DEB_BUILD="${BUILD_ROOT}/debbuild"

# Log functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root or with sudo"
        exit 1
    fi
}

# Install build dependencies
install_dependencies() {
    log_info "Installing build dependencies..."

    # RPM build tools
    dnf install -y rpm-build rpmdevtools

    # Development tools
    dnf groupinstall -y "Development Tools"

    # Runtime dependencies
    dnf install -y ncurses-devel jansson-devel

    log_success "Dependencies installed"
}

# Clean previous build artifacts
clean_build() {
    log_info "Cleaning previous build artifacts..."
    rm -rf "${BUILD_ROOT}"
    mkdir -p "${BUILD_ROOT}"
    log_success "Build directory cleaned"
}

# Build the binary
build_binary() {
    log_info "Building trivytui binary..."

    cd "${SCRIPT_DIR}"
    make clean
    make

    if [[ ! -f "${SCRIPT_DIR}/trivytui" ]]; then
        log_error "Build failed - trivytui binary not found"
        exit 1
    fi

    log_success "Binary built successfully"
}

# Run tests
run_tests() {
    log_info "Running unit tests..."

    cd "${SCRIPT_DIR}"
    if make test; then
        log_success "All tests passed"
    else
        log_warning "Some tests failed, but continuing with package build"
    fi
}

# Create RPM package
build_rpm() {
    log_info "Building RPM package..."

    # Setup RPM build directory structure
    mkdir -p "${RPM_BUILD}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

    # Create spec file
    cat > "${RPM_BUILD}/SPECS/${PKG_NAME}.spec" <<EOF
Name:           ${PKG_NAME}
Version:        ${PKG_VERSION}
Release:        ${PKG_RELEASE}%{?dist}
Summary:        ${PKG_SUMMARY}
License:        ${PKG_LICENSE}
URL:            ${PKG_URL}
BuildArch:      ${PKG_ARCH}

Requires:       ncurses-libs >= 6.1
Requires:       jansson >= 2.11

%description
${PKG_DESCRIPTION}

%prep
# No prep needed - binary already built

%build
# No build needed - binary already built

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_docdir}/%{name}
install -m 0755 ${SCRIPT_DIR}/trivytui %{buildroot}%{_bindir}/trivytui
install -m 0644 ${SCRIPT_DIR}/README.md %{buildroot}%{_docdir}/%{name}/README.md

%files
%{_bindir}/trivytui
%doc %{_docdir}/%{name}/README.md

%changelog
* $(date '+%a %b %d %Y') ${MAINTAINER} - ${PKG_VERSION}-${PKG_RELEASE}
- Version 0.9.2 release
- Added airgapped scripts
- Added history view with scan tracking and security scores
- Added search & filter in report viewer
- Added export to HTML and Markdown formats
- Security hardening with input validation and buffer overflow protection
- Comprehensive unit tests and documentation

* Mon Jan 01 2025 ${MAINTAINER} - 0.9.0-1
- Initial release
- Filesystem and Docker image scanning
- Interactive TUI with ncurses
- Trivy version detection and fallback support
EOF

    # Build RPM
    rpmbuild --define "_topdir ${RPM_BUILD}" \
             -bb "${RPM_BUILD}/SPECS/${PKG_NAME}.spec"

    # Copy RPM to build root
    find "${RPM_BUILD}/RPMS" -name "*.rpm" -exec cp {} "${BUILD_ROOT}/" \;

    log_success "RPM package created: ${BUILD_ROOT}/${PKG_NAME}-${PKG_VERSION}-${PKG_RELEASE}.*.rpm"
}

# Create DEB package manually (without dpkg-deb)
#
# Since dpkg-deb is not available on Rocky Linux, we manually construct the
# DEB package using standard UNIX tools (tar and ar). A .deb file is simply
# an 'ar' archive containing three files in specific order:
#   1. debian-binary: Contains "2.0" (package format version)
#   2. control.tar.gz: Package metadata (name, version, dependencies)
#   3. data.tar.gz: Actual files to install
build_deb() {
    log_info "Building DEB package..."

    # Create DEB directory structure matching Debian FHS
    local DEB_PKG_DIR="${DEB_BUILD}/${PKG_NAME}_${PKG_VERSION}-${PKG_RELEASE}"
    mkdir -p "${DEB_PKG_DIR}/DEBIAN"
    mkdir -p "${DEB_PKG_DIR}/usr/bin"
    mkdir -p "${DEB_PKG_DIR}/usr/share/doc/${PKG_NAME}"

    # Create control file with package metadata
    # Format: https://www.debian.org/doc/debian-policy/ch-controlfields.html
    cat > "${DEB_PKG_DIR}/DEBIAN/control" <<EOF
Package: ${PKG_NAME}
Version: ${PKG_VERSION}-${PKG_RELEASE}
Section: utils
Priority: optional
Architecture: amd64
Depends: libncurses6 (>= 6.0), libjansson4 (>= 2.7)
Maintainer: ${MAINTAINER}
Description: ${PKG_SUMMARY}
 ${PKG_DESCRIPTION}
Homepage: ${PKG_URL}
EOF

    # Install files to package directory
    install -m 0755 "${SCRIPT_DIR}/trivytui" "${DEB_PKG_DIR}/usr/bin/trivytui"
    install -m 0644 "${SCRIPT_DIR}/README.md" "${DEB_PKG_DIR}/usr/share/doc/${PKG_NAME}/README.md"

    # Create debian-binary file (indicates DEB format version 2.0)
    echo "2.0" > "${DEB_BUILD}/debian-binary"

    # Create control archive (package metadata)
    cd "${DEB_PKG_DIR}/DEBIAN"
    tar czf "${DEB_BUILD}/control.tar.gz" ./control
    cd "${SCRIPT_DIR}"

    # Create data archive (files to install on target system)
    cd "${DEB_PKG_DIR}"
    tar czf "${DEB_BUILD}/data.tar.gz" ./usr
    cd "${SCRIPT_DIR}"

    # Combine into .deb using ar archiver
    # Order is critical: debian-binary, control.tar.gz, data.tar.gz
    cd "${DEB_BUILD}"
    ar r "${BUILD_ROOT}/${PKG_NAME}_${PKG_VERSION}-${PKG_RELEASE}_amd64.deb" \
        debian-binary control.tar.gz data.tar.gz
    cd "${SCRIPT_DIR}"

    log_success "DEB package created: ${BUILD_ROOT}/${PKG_NAME}_${PKG_VERSION}-${PKG_RELEASE}_amd64.deb"
}

# Create tarball
create_tarball() {
    log_info "Creating source tarball..."

    cd "${SCRIPT_DIR}"
    tar czf "${BUILD_ROOT}/${PKG_NAME}-${PKG_VERSION}.tar.gz" \
        --exclude=build \
        --exclude=.git \
        --exclude='*.o' \
        --exclude=trivytui \
        --exclude=test_trivytui \
        main.c test_trivytui.c Makefile README.md build-packages.sh

    log_success "Source tarball created: ${BUILD_ROOT}/${PKG_NAME}-${PKG_VERSION}.tar.gz"
}

# Generate checksums
generate_checksums() {
    log_info "Generating checksums..."

    cd "${BUILD_ROOT}"

    # SHA256 checksums
    {
        sha256sum *.rpm 2>/dev/null || true
        sha256sum *.deb 2>/dev/null || true
        sha256sum *.tar.gz 2>/dev/null || true
    } > SHA256SUMS

    log_success "Checksums generated: ${BUILD_ROOT}/SHA256SUMS"
}

# Display summary
show_summary() {
    echo ""
    echo "=========================================="
    log_success "Package build completed successfully!"
    echo "=========================================="
    echo ""
    echo "Build artifacts:"
    ls -lh "${BUILD_ROOT}"/*.rpm "${BUILD_ROOT}"/*.deb "${BUILD_ROOT}"/*.tar.gz 2>/dev/null || true
    echo ""
    echo "Installation instructions:"
    echo ""
    echo "  RPM (Rocky/RHEL/CentOS/Fedora):"
    echo "    sudo dnf install ${BUILD_ROOT}/${PKG_NAME}-${PKG_VERSION}-${PKG_RELEASE}.*.rpm"
    echo ""
    echo "  DEB (Debian/Ubuntu):"
    echo "    sudo apt install ${BUILD_ROOT}/${PKG_NAME}_${PKG_VERSION}-${PKG_RELEASE}_amd64.deb"
    echo ""
    echo "  Or install manually:"
    echo "    sudo rpm -ivh ${BUILD_ROOT}/${PKG_NAME}-${PKG_VERSION}-${PKG_RELEASE}.*.rpm"
    echo "    sudo dpkg -i ${BUILD_ROOT}/${PKG_NAME}_${PKG_VERSION}-${PKG_RELEASE}_amd64.deb"
    echo ""
    echo "After installation, run: trivytui"
    echo ""
}

# Main execution
main() {
    log_info "Starting package build for ${PKG_NAME} v${PKG_VERSION}"

    check_root
    install_dependencies
    clean_build
    build_binary
    run_tests
    build_rpm
    build_deb
    create_tarball
    generate_checksums
    show_summary

    log_success "Build process complete!"
}

# Run main function
main "$@"
