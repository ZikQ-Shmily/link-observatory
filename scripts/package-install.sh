#!/usr/bin/env bash
set -euo pipefail

tag=${1:-}
repository=${2:-}
amd64_hash=${3:-}
arm64_hash=${4:-}
[[ $tag =~ ^v[0-9]+(\.[0-9]+){2}(-[A-Za-z0-9.-]+)?$ &&
   $repository =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ &&
   $amd64_hash =~ ^[a-f0-9]{64}$ && $arm64_hash =~ ^[a-f0-9]{64}$ ]] ||
    { printf 'Usage: %s TAG OWNER/REPO AMD64_SHA256 ARM64_SHA256\n' "$0" >&2; exit 1; }
release_url="https://github.com/$repository/releases/download/$tag"
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)

# The header and installer are a single compound command, so a partial heredoc
# cannot run the installer. A file copy lets the installer keep its local menu.
cat <<'HEADER'
#!/usr/bin/env bash
{
    set +x +v
    set -euo pipefail
    umask 077
    installer=$(mktemp)
    trap 'rm -f -- "$installer"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    cat > "$installer" <<'LINK_OBSERVATORY_INSTALLER'
HEADER
sed -e "s/^installer_release_tag=$/installer_release_tag='$tag'/" \
    -e "s/^installer_sha_amd64=$/installer_sha_amd64='$amd64_hash'/" \
    -e "s/^installer_sha_arm64=$/installer_sha_arm64='$arm64_hash'/" \
    "$source_dir/install.sh"
cat <<FOOTER
LINK_OBSERVATORY_INSTALLER
    bash "\$installer" --release-url '$release_url' --gh-proxy '' "\$@"
}
FOOTER
