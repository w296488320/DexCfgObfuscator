#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: $0 <staging-maven-repository> <pages-worktree> <version>" >&2
}

fail() {
    echo "GitHub Pages Maven publish failed: $*" >&2
    exit 1
}

if [[ "$#" -ne 3 ]]; then
    usage
    exit 2
fi

staging_repository="$1"
pages_worktree="$2"
version="$3"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    fail "version must be a safe semantic version, got '$version'"
fi
if [[ ! -d "$staging_repository" || -L "$staging_repository" ]]; then
    fail "staging Maven repository is not a directory: $staging_repository"
fi
if [[ ! -d "$pages_worktree" || -L "$pages_worktree" ]]; then
    fail "Pages worktree is not a directory: $pages_worktree"
fi
if find "$staging_repository" -type l -print -quit | grep -q .; then
    fail "staging Maven repository must not contain symbolic links"
fi
if find "$pages_worktree" -type l -print -quit | grep -q .; then
    fail "Pages worktree must not contain symbolic links"
fi

group_id='io.github.w296488320'
artifact_id='dex-cfg-obfuscator'
plugin_id='io.github.w296488320.dexcfgobf'
marker_artifact_id="${plugin_id}.gradle.plugin"

implementation_relative="io/github/w296488320/dex-cfg-obfuscator/$version"
marker_relative="io/github/w296488320/dexcfgobf/$marker_artifact_id/$version"
implementation_source="$staging_repository/$implementation_relative"
marker_source="$staging_repository/$marker_relative"

[[ -d "$implementation_source" ]] \
    || fail "implementation publication is missing: $implementation_source"
[[ -d "$marker_source" ]] \
    || fail "plugin marker publication is missing: $marker_source"

implementation_base="$artifact_id-$version"
marker_base="$marker_artifact_id-$version"
implementation_pom="$implementation_source/$implementation_base.pom"
marker_pom="$marker_source/$marker_base.pom"

required_artifacts=(
    "$implementation_source/$implementation_base.jar"
    "$implementation_source/$implementation_base-sources.jar"
    "$implementation_source/$implementation_base-javadoc.jar"
    "$implementation_source/$implementation_base.module"
    "$implementation_pom"
    "$marker_pom"
)

for artifact in "${required_artifacts[@]}"; do
    [[ -s "$artifact" ]] || fail "required publication artifact is missing or empty: $artifact"
done

# java-gradle-plugin must produce exactly the implementation publication and its
# plugin marker publication. Extra POMs here indicate an accidental public API.
pom_count=0
while IFS= read -r -d '' published_pom; do
    case "$published_pom" in
        "$implementation_pom"|"$marker_pom") ;;
        *) fail "unexpected Maven publication POM: $published_pom" ;;
    esac
    pom_count=$((pom_count + 1))
done < <(find "$staging_repository" -type f -name '*.pom' -print0)
[[ "$pom_count" -eq 2 ]] \
    || fail "expected exactly 2 Maven publications, found $pom_count"

require_pom_text() {
    local pom_file="$1"
    local expected_text="$2"
    grep -Fq "$expected_text" "$pom_file" \
        || fail "POM is missing '$expected_text': $pom_file"
}

require_pom_text "$implementation_pom" "<groupId>$group_id</groupId>"
require_pom_text "$implementation_pom" "<artifactId>$artifact_id</artifactId>"
require_pom_text "$implementation_pom" "<version>$version</version>"
require_pom_text "$marker_pom" "<groupId>$plugin_id</groupId>"
require_pom_text "$marker_pom" "<artifactId>$marker_artifact_id</artifactId>"
require_pom_text "$marker_pom" "<version>$version</version>"

# These three values occur in the marker dependency and prove that Gradle's
# plugins DSL will resolve the marker to this exact implementation component.
require_pom_text "$marker_pom" "<groupId>$group_id</groupId>"
require_pom_text "$marker_pom" "<artifactId>$artifact_id</artifactId>"
marker_version_occurrences="$(
    grep -Fc "<version>$version</version>" "$marker_pom" || true
)"
[[ "$marker_version_occurrences" -eq 2 ]] \
    || fail "plugin marker must reference implementation version $version: $marker_pom"

plugin_descriptor="META-INF/gradle-plugins/$plugin_id.properties"
if ! jar tf "$implementation_source/$implementation_base.jar" \
        | grep -Fxq "$plugin_descriptor"; then
    fail "implementation JAR is missing plugin descriptor $plugin_descriptor"
fi

digest_file() {
    local algorithm="$1"
    local input_file="$2"
    case "$algorithm" in
        md5)
            if command -v md5sum >/dev/null 2>&1; then
                md5sum "$input_file" | awk '{print $1}'
            elif command -v md5 >/dev/null 2>&1; then
                md5 -q "$input_file"
            else
                fail 'neither md5sum nor md5 is available'
            fi
            ;;
        sha1) shasum -a 1 "$input_file" | awk '{print $1}' ;;
        sha256) shasum -a 256 "$input_file" | awk '{print $1}' ;;
        sha512) shasum -a 512 "$input_file" | awk '{print $1}' ;;
        *) fail "unsupported digest algorithm: $algorithm" ;;
    esac
}

for artifact in "${required_artifacts[@]}"; do
    for algorithm in md5 sha1 sha256 sha512; do
        checksum_file="$artifact.$algorithm"
        [[ -s "$checksum_file" ]] \
            || fail "publication checksum is missing: $checksum_file"
        expected_digest="$(tr -d '[:space:]' < "$checksum_file")"
        actual_digest="$(digest_file "$algorithm" "$artifact")"
        [[ "$expected_digest" == "$actual_digest" ]] \
            || fail "publication checksum mismatch: $checksum_file"
    done
done

repository_root="$pages_worktree/maven-repo"
implementation_destination="$repository_root/$implementation_relative"
marker_destination="$repository_root/$marker_relative"

implementation_exists=false
marker_exists=false
[[ -e "$implementation_destination" || -L "$implementation_destination" ]] \
    && implementation_exists=true
[[ -e "$marker_destination" || -L "$marker_destination" ]] \
    && marker_exists=true

# Maven releases are immutable. A complete, byte-identical pair is an
# idempotent workflow retry; a half-published or changed pair is never repaired
# by overwriting files under the same version.
if [[ "$implementation_exists" != "$marker_exists" ]]; then
    fail "refusing half-published version: implementation=$implementation_exists marker=$marker_exists"
fi

publication_is_new=true
if [[ "$implementation_exists" == true ]]; then
    if ! diff -qr "$implementation_source" "$implementation_destination" >/dev/null 2>&1; then
        fail "refusing to overwrite changed implementation version directory: $implementation_destination"
    fi
    if ! diff -qr "$marker_source" "$marker_destination" >/dev/null 2>&1; then
        fail "refusing to overwrite changed plugin marker version directory: $marker_destination"
    fi
    publication_is_new=false
fi

write_maven_metadata() {
    local published_group_id="$1"
    local published_artifact_id="$2"
    local artifact_directory="$3"
    local metadata_file="$artifact_directory/maven-metadata.xml"
    local temporary_metadata="$artifact_directory/.maven-metadata.xml.tmp"
    local last_updated
    local latest_version=''
    local candidate_version
    local -a published_versions=()

    while IFS= read -r candidate_version; do
        [[ -n "$candidate_version" ]] || continue
        if [[ "$candidate_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            published_versions+=("$candidate_version")
            latest_version="$candidate_version"
        fi
    done < <(find "$artifact_directory" -mindepth 1 -maxdepth 1 -type d \
        -exec basename {} \; | LC_ALL=C sort -V)

    [[ "${#published_versions[@]}" -gt 0 ]] \
        || fail "no version directories found below $artifact_directory"
    last_updated="$(date -u '+%Y%m%d%H%M%S')"

    {
        printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>'
        printf '%s\n' '<metadata>'
        printf '  <groupId>%s</groupId>\n' "$published_group_id"
        printf '  <artifactId>%s</artifactId>\n' "$published_artifact_id"
        printf '%s\n' '  <versioning>'
        printf '    <latest>%s</latest>\n' "$latest_version"
        printf '    <release>%s</release>\n' "$latest_version"
        printf '%s\n' '    <versions>'
        for candidate_version in "${published_versions[@]}"; do
            printf '      <version>%s</version>\n' "$candidate_version"
        done
        printf '%s\n' '    </versions>'
        printf '    <lastUpdated>%s</lastUpdated>\n' "$last_updated"
        printf '%s\n' '  </versioning>'
        printf '%s\n' '</metadata>'
    } > "$temporary_metadata"
    mv "$temporary_metadata" "$metadata_file"

    for algorithm in md5 sha1 sha256 sha512; do
        digest_file "$algorithm" "$metadata_file" > "$metadata_file.$algorithm"
    done
}

validate_existing_metadata() {
    local metadata_file="$1"
    local algorithm
    local checksum_file
    local expected_digest
    local actual_digest

    [[ -s "$metadata_file" ]] \
        || fail "published version has no Maven metadata: $metadata_file"
    grep -Fq "<version>$version</version>" "$metadata_file" \
        || fail "Maven metadata does not list idempotent version $version: $metadata_file"
    for algorithm in md5 sha1 sha256 sha512; do
        checksum_file="$metadata_file.$algorithm"
        [[ -s "$checksum_file" ]] \
            || fail "Maven metadata checksum is missing: $checksum_file"
        expected_digest="$(tr -d '[:space:]' < "$checksum_file")"
        actual_digest="$(digest_file "$algorithm" "$metadata_file")"
        [[ "$expected_digest" == "$actual_digest" ]] \
            || fail "Maven metadata checksum mismatch: $checksum_file"
    done
}

implementation_artifact_directory="$(dirname "$implementation_destination")"
marker_artifact_directory="$(dirname "$marker_destination")"
if [[ "$publication_is_new" == true ]]; then
    mkdir -p "$implementation_artifact_directory"
    mkdir -p "$marker_artifact_directory"
    cp -R "$implementation_source" "$implementation_destination"
    cp -R "$marker_source" "$marker_destination"
    write_maven_metadata "$group_id" "$artifact_id" "$implementation_artifact_directory"
    write_maven_metadata "$plugin_id" "$marker_artifact_id" "$marker_artifact_directory"
else
    # Do not regenerate metadata here: lastUpdated is part of the published
    # repository state and must stay byte-identical on an idempotent retry.
    validate_existing_metadata "$implementation_artifact_directory/maven-metadata.xml"
    validate_existing_metadata "$marker_artifact_directory/maven-metadata.xml"
fi

# A branch-backed repository remains directly browsable even when the Pages
# deployment source is GitHub Actions.
touch "$pages_worktree/.nojekyll"
if [[ ! -e "$pages_worktree/index.html" ]]; then
    {
        printf '%s\n' '<!doctype html>'
        printf '%s\n' '<html lang="en"><meta charset="utf-8">'
        printf '%s\n' '<title>DexCfgObfuscator Maven repository</title>'
        printf '%s\n' '<h1>DexCfgObfuscator Maven repository</h1>'
        printf '%s\n' '<p>Public Gradle plugin artifacts are available under <code>maven-repo/</code>.</p>'
        printf '%s\n' '</html>'
    } > "$pages_worktree/index.html"
fi

if [[ "$publication_is_new" == true ]]; then
    echo "Validated and merged 2 immutable Maven publications for version $version."
else
    echo "Validated 2 byte-identical Maven publications already present for version $version."
fi
