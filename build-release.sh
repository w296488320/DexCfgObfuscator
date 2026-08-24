#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir"

version="$(sed -n "s/^version = '\([^']*\)'$/\1/p" build.gradle | head -n 1)"
if [[ -z "$version" || ! "$version" =~ ^[0-9A-Za-z._-]+$ ]]; then
    echo "无法从 build.gradle 解析安全的 version。" >&2
    exit 1
fi

implementation_dir="$script_dir/maven-repo/com/hunter/dex-cfg-obfuscator/$version"
marker_dir="$script_dir/maven-repo/com/hunter/dexcfgobf/com.hunter.dexcfgobf.gradle.plugin/$version"
release_dir="$script_dir/release"
archive="$release_dir/dex-cfg-obfuscator-$version-maven-repo.zip"
checksum="$archive.sha256"

# 发布版本不可覆盖。已有任一坐标或分发包时必须提升 version，避免 Hunter 与其他宿主
# 在相同插件版本号下解析到不同字节码。
for immutable_target in "$implementation_dir" "$marker_dir" "$archive" "$checksum"; do
    if [[ -e "$immutable_target" ]]; then
        echo "拒绝覆盖已存在的发布目标：$immutable_target" >&2
        echo "请先提升 build.gradle 中的 version，再重新发布。" >&2
        exit 1
    fi
done

# 在写 Maven 仓库前完成所有廉价前置检查；发布中途失败时只清理本次版本的精确目标，
# 根级 maven-metadata 会由下一次 publish 重新生成，因而同一未完成版本可以安全重试。
command -v jar >/dev/null 2>&1 || {
    echo "缺少 JDK jar 命令，无法生成发布包。" >&2
    exit 1
}
if ! command -v shasum >/dev/null 2>&1 && ! command -v sha256sum >/dev/null 2>&1; then
    echo "缺少 shasum/sha256sum，无法生成 SHA-256。" >&2
    exit 1
fi
for documentation in README.md doc/README_CN.md doc/README_EN.md; do
    if [[ ! -s "$script_dir/$documentation" ]]; then
        echo "发布校验失败，文档不存在或为空：$script_dir/$documentation" >&2
        exit 1
    fi
done

cleanup_new_version=false
temporary_dir=""
cleanup_release_attempt() {
    status=$?
    if [[ "$cleanup_new_version" == true && $status -ne 0 ]]; then
        rm -rf -- "$implementation_dir" "$marker_dir"
        rm -f -- "$archive" "$checksum"
        echo "已清理未完成版本 $version 的局部发布目标，可修复后重试。" >&2
    fi
    if [[ -n "$temporary_dir" && -d "$temporary_dir" ]]; then
        rm -rf -- "$temporary_dir"
    fi
    exit "$status"
}
trap cleanup_release_attempt EXIT

echo "[1/4] 测试并校验 Gradle 插件 $version"
gradle_flags=(--offline --no-daemon --no-configuration-cache --no-parallel)
./gradlew "${gradle_flags[@]}" clean test validatePlugins

echo "[2/4] 发布到 $script_dir/maven-repo"
cleanup_new_version=true
./gradlew "${gradle_flags[@]}" publish

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
mkdir -p "$release_dir"
temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/dex-cfg-obfuscator-release.XXXXXX")"
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
fi
cleanup_new_version=false

echo "[4/4] 完成"
echo "版本：$version"
echo "发布包：$archive"
echo "校验值：$checksum"
echo "接收方解压后，在 settings.gradle 的 pluginManagement.repositories 中指向 maven-repo/。"
