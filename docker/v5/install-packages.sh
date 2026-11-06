#!/bin/sh
# Resolve exclusively against the signed snapshot metadata. Mirrors supply only
# identical package bytes, checked against the hash printed by apt.
set -eu

helper=${CLAASP_APT_HELPER:-/usr/lib/apt/apt-helper}
archives=${CLAASP_APT_ARCHIVES:-/var/cache/apt/archives}

if apt-get -o Acquire::Retries=0 \
    -o Acquire::https::snapshot.ubuntu.com::Verify-Peer=false \
    install --no-install-recommends -y "$@"; then
    exit 0
fi

uris=$(mktemp)
trap 'rm -f "$uris"' EXIT HUP INT TERM
apt-get -o Acquire::https::snapshot.ubuntu.com::Verify-Peer=false \
    -o Acquire::ForceHash=SHA256 --print-uris install --no-install-recommends -y "$@" > "$uris"

while IFS="'" read -r prefix uri rest; do
    case "$uri" in
        https://snapshot.ubuntu.com/ubuntu/*/pool/*) ;;
        '') continue ;;
        *) echo "Unexpected package source: $uri" >&2; exit 1 ;;
    esac
    # apt emits: 'URI' filename size SHA256:digest
    read -r filename size hash extra <<EOF
$rest
EOF
    case "$filename" in
        ''|*/*|.|..) echo 'Invalid package filename' >&2; exit 1 ;;
    esac
    case "$hash" in
        SHA256:*) ;;
        *) echo 'Snapshot package has no SHA256 digest' >&2; exit 1 ;;
    esac
    target="$archives/$filename"
    pool_path=${uri#*/pool/}
    downloaded=false
    for source in \
        "http://archive.ubuntu.com/ubuntu/pool/$pool_path" \
        "http://security.ubuntu.com/ubuntu/pool/$pool_path" \
        "http://ports.ubuntu.com/ubuntu-ports/pool/$pool_path" \
        "$uri"; do
        # Ubuntu's ordinary apt mirrors support HTTP. Integrity comes from the
        # SHA256 in the signed snapshot index, including during CA bootstrap.
        if "$helper" -o Acquire::Retries=2 \
            -o Acquire::https::snapshot.ubuntu.com::Verify-Peer=false \
            download-file "$source" "$target" "$hash"; then
            downloaded=true
            break
        fi
        rm -f "$target"
    done
    if [ "$downloaded" != true ]; then
        echo "No mirror supplied the snapshot-verified package: $filename" >&2
        exit 1
    fi
done < "$uris"

# Reuse the verified archives with the original snapshot package resolver.
apt-get -o Acquire::https::snapshot.ubuntu.com::Verify-Peer=false \
    install --no-install-recommends -y "$@"
