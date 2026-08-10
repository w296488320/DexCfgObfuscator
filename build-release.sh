#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir"

version="$(sed -n "s/^version = '\([^']*\)'$/\1/p" build.gradle | head -n 1)"
if [[ -z "$version" || ! "$version" =~ ^[0-9A-Za-z._-]+$ ]]; then
    echo "无法从 build.gradle 解析安全的 version。" >&2
    exit 1
fi

echo "[1/4] 测试并校验 Gradle 插件 $version"
./gradlew clean test validatePlugins

echo "[2/4] 发布到 $script_dir/maven-repo"
./gradlew publish

implementation_dir="$script_dir/maven-repo/com/hunter/dex-cfg-obfuscator/$version"
marker_dir="$script_dir/maven-repo/com/hunter/dexcfgobf/com.hunter.dexcfgobf.gradle.plugin/$version"
implementation_jar="$implementation_dir/dex-cfg-obfuscator-$version.jar"
marker_pom="$marker_dir/com.hunter.dexcfgobf.gradle.plugin-$version.pom"

for required_file in \
    "$implementation_jar" \
    "$marker_pom" \
    "$script_dir/README.md" \
    "$script_dir/doc/README_CN.md" \
    "$script_dir/doc/README_EN.md"; do
    if [[ ! -s "$required_file" ]]; then
        echo "发布校验失败，文件不存在或为空：$required_file" >&2
        exit 1
    fi
done

echo "[3/4] 生成可分发 ZIP"
release_dir="$script_dir/release"
mkdir -p "$release_dir"
archive="$release_dir/dex-cfg-obfuscator-$version-maven-repo.zip"
checksum="$archive.sha256"
temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/dex-cfg-obfuscator-release.XXXXXX")"
trap 'rm -rf -- "$temporary_dir"' EXIT
temporary_archive="$temporary_dir/$(basename "$archive")"

# JDK 是构建插件的必备环境；用 jar 生成标准 ZIP，避免额外依赖 zip/ditto。
jar --create --file "$temporary_archive" \
    -C "$script_dir" maven-repo \
    -C "$script_dir" README.md \
    -C "$script_dir" doc
jar --list --file "$temporary_archive" | grep -Fqx \
    "maven-repo/com/hunter/dex-cfg-obfuscator/$version/dex-cfg-obfuscator-$version.jar"
jar --list --file "$temporary_archive" | grep -Fqx \
    "maven-repo/com/hunter/dexcfgobf/com.hunter.dexcfgobf.gradle.plugin/$version/com.hunter.dexcfgobf.gradle.plugin-$version.pom"
jar --list --file "$temporary_archive" | grep -Fqx "doc/README_CN.md"
jar --list --file "$temporary_archive" | grep -Fqx "doc/README_EN.md"
mv -f -- "$temporary_archive" "$archive"

if command -v shasum >/dev/null 2>&1; then
    (cd "$release_dir" && shasum -a 256 "$(basename "$archive")") > "$checksum"
elif command -v sha256sum >/dev/null 2>&1; then
    (cd "$release_dir" && sha256sum "$(basename "$archive")") > "$checksum"
else
    echo "缺少 shasum/sha256sum，无法生成 SHA-256。" >&2
    exit 1
fi

echo "[4/4] 完成"
echo "版本：$version"
echo "发布包：$archive"
echo "校验值：$checksum"
echo "接收方解压后，在 settings.gradle 的 pluginManagement.repositories 中指向 maven-repo/。"
