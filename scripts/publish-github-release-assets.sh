#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "GitHub Release publish failed: $*" >&2
    exit 1
}

if [[ "$#" -lt 3 ]]; then
    echo "Usage: $0 <vX.Y.Z> <asset> <asset> [asset ...]" >&2
    exit 2
fi

release_tag="$1"
shift
[[ "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || fail "invalid release tag: $release_tag"
[[ -n "${GH_REPO:-}" ]] || fail 'GH_REPO is required'
[[ -n "${GH_TOKEN:-}" ]] || fail 'GH_TOKEN is required'
command -v gh >/dev/null 2>&1 || fail 'GitHub CLI (gh) is required'

temporary_directory="$(mktemp -d "${RUNNER_TEMP:-/tmp}/dexcfg-release-assets.XXXXXX")"
cleanup() {
    rm -rf -- "$temporary_directory"
}
trap cleanup EXIT

release_exists=false
release_is_draft=false
release_error="$temporary_directory/release-error.log"
if gh release view "$release_tag" --repo "$GH_REPO" >/dev/null 2>"$release_error"; then
    release_exists=true
    release_is_draft="$(
        gh release view "$release_tag" --repo "$GH_REPO" \
            --json isDraft --jq '.isDraft'
    )"
elif grep -Eqi 'release not found|HTTP 404|not found' "$release_error"; then
    gh release create "$release_tag" \
        --repo "$GH_REPO" \
        --verify-tag \
        --draft \
        --title "DexCfgObfuscator ${release_tag#v}" \
        --generate-notes
    release_exists=true
    release_is_draft=true
else
    sed 's/^/gh: /' "$release_error" >&2
    fail "could not inspect release $release_tag"
fi

[[ "$release_exists" == true ]] || fail "could not create release $release_tag"
existing_assets="$temporary_directory/existing-assets.txt"
gh release view "$release_tag" --repo "$GH_REPO" \
    --json assets --jq '.assets[].name' > "$existing_assets"

declare -a seen_asset_names=()
for asset in "$@"; do
    [[ -s "$asset" ]] || fail "release asset is missing or empty: $asset"
    asset_name="$(basename "$asset")"
    if [[ "${#seen_asset_names[@]}" -gt 0 ]]; then
        for seen_name in "${seen_asset_names[@]}"; do
            [[ "$seen_name" != "$asset_name" ]] \
                || fail "duplicate release asset name: $asset_name"
        done
    fi
    seen_asset_names+=("$asset_name")

    if grep -Fxq "$asset_name" "$existing_assets"; then
        asset_download_directory="$temporary_directory/$asset_name.download"
        mkdir -p "$asset_download_directory"
        gh release download "$release_tag" \
            --repo "$GH_REPO" \
            --pattern "$asset_name" \
            --dir "$asset_download_directory"
        downloaded_asset="$asset_download_directory/$asset_name"
        [[ -s "$downloaded_asset" ]] \
            || fail "downloaded release asset is missing: $asset_name"
        cmp -s "$asset" "$downloaded_asset" \
            || fail "refusing to replace different existing release asset: $asset_name"
        echo "Release asset is already byte-identical: $asset_name"
    else
        gh release upload "$release_tag" "$asset" --repo "$GH_REPO"
        echo "Uploaded immutable release asset: $asset_name"
    fi
done

if [[ "$release_is_draft" == true ]]; then
    gh release edit "$release_tag" --repo "$GH_REPO" --draft=false
fi

echo "GitHub Release $release_tag is published with verified immutable assets."
