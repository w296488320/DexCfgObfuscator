#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir"

is_true() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|on|ON) return 0 ;;
        *) return 1 ;;
    esac
}

version="$(sed -n "s/^version = '\([^']*\)'$/\1/p" build.gradle | head -n 1)"
if [[ -z "$version" ]]; then
    version="$(sed -n \
        "/^def pomVersion = /,/^def publicPluginId = /s/.*\\.getOrElse('\([^']*\)').*/\1/p" \
        build.gradle | head -n 1)"
fi
if [[ -z "$version" || ! "$version" =~ ^[0-9A-Za-z._-]+$ ]]; then
    echo "无法从 build.gradle 解析安全的 version。" >&2
    exit 1
fi

if [[ -n "${DEXCFG_EXPECTED_VERSION:-}" && "$version" != "$DEXCFG_EXPECTED_VERSION" ]]; then
    echo "版本不匹配：build.gradle=$version，期望=$DEXCFG_EXPECTED_VERSION。" >&2
    exit 1
fi

release_dir="$script_dir/release"
archive="$release_dir/dex-cfg-obfuscator-$version-maven-repo.zip"
checksum="$archive.sha256"

# 同一版本的公开发布物必须不可变。需要重发时应提升 build.gradle 中的版本号。
for immutable_target in "$archive" "$checksum"; do
    if [[ -e "$immutable_target" ]]; then
        echo "拒绝覆盖已存在的发布目标：$immutable_target" >&2
        echo "请先提升 build.gradle 中的 version，再重新发布。" >&2
        exit 1
    fi
done

# 正式发布默认要求源码与文档均已提交。开发阶段可显式设置
# DEXCFG_ALLOW_DIRTY=true 做本地预演，但不应上传该预演产物。
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    dirty_files="$(git status --porcelain --untracked-files=all -- .)"
    if [[ -n "$dirty_files" ]] && ! is_true "${DEXCFG_ALLOW_DIRTY:-false}"; then
        echo "发布校验失败：工作树不是干净状态。请先提交或移走下列改动：" >&2
        printf '%s\n' "$dirty_files" >&2
        echo "仅本地预演可显式设置 DEXCFG_ALLOW_DIRTY=true。" >&2
        exit 1
    fi
fi

command -v jar >/dev/null 2>&1 || {
    echo "缺少 JDK jar 命令，无法生成发布包。" >&2
    exit 1
}
if ! command -v shasum >/dev/null 2>&1 && ! command -v sha256sum >/dev/null 2>&1; then
    echo "缺少 shasum/sha256sum，无法生成 SHA-256。" >&2
    exit 1
fi

for required_document in \
    README.md \
    doc/README_CN.md \
    doc/README_EN.md \
    LICENSE \
    THIRD_PARTY_NOTICES.md; do
    if [[ ! -s "$script_dir/$required_document" ]]; then
        echo "发布校验失败，文档不存在或为空：$script_dir/$required_document" >&2
        exit 1
    fi
done

for versioned_document in README.md doc/README_CN.md doc/README_EN.md; do
    if ! grep -Fq "id 'io.github.w296488320.dexcfgobf' version '$version'" \
            "$script_dir/$versioned_document"; then
        echo "发布校验失败，文档中的插件版本未同步为 $version：" \
            "$script_dir/$versioned_document" >&2
        exit 1
    fi
done

temp_base="${TMPDIR:-/tmp}"
temp_base="${temp_base%/}"
temporary_dir="$(mktemp -d "$temp_base/dex-cfg-obfuscator-release.XXXXXX")"
staging_repo="$temporary_dir/maven-repo"
package_root="$temporary_dir/package"
temporary_archive="$temporary_dir/$(basename "$archive")"
archive_created=false

cleanup_release_attempt() {
    status=$?
    if [[ "$status" -ne 0 && "$archive_created" == true ]]; then
        rm -f -- "$archive" "$checksum"
        echo "已清理未完成的 $version 发布包，可修复后重试。" >&2
    fi
    rm -rf -- "$temporary_dir"
    exit "$status"
}
trap cleanup_release_attempt EXIT

gradle_flags=(--no-daemon --no-configuration-cache --no-parallel)
if is_true "${DEXCFG_OFFLINE:-false}"; then
    gradle_flags+=(--offline)
    echo "已启用显式离线模式（DEXCFG_OFFLINE=true）。"
fi
publication_properties=(
    "-PPOM_GROUP_ID=io.github.w296488320"
    "-PPOM_ARTIFACT_ID=dex-cfg-obfuscator"
    "-PPOM_VERSION=$version"
    "-PPOM_PLUGIN_ID=io.github.w296488320.dexcfgobf"
    "-PcentralPublishing=false"
)

run_local_gradle() {
    # 本地/GitHub Release 打包绝不能因为调用者遗留的 Central 环境变量而外发产物。
    env \
        -u MAVEN_CENTRAL_PUBLISHING \
        -u ORG_GRADLE_PROJECT_centralPublishing \
        -u ORG_GRADLE_PROJECT_centralBundleRepo \
        ./gradlew "${publication_properties[@]}" "$@"
}

echo "[1/4] 测试并校验 Gradle 插件 $version"
run_local_gradle "${gradle_flags[@]}" clean test validatePlugins

echo "[2/4] 发布到隔离的临时 Maven 仓库"
run_local_gradle \
    "-PdexCfgObfuscatorPublishRepo=$staging_repo" \
    "${gradle_flags[@]}" \
    publishAllPublicationsToLocalPluginRepoRepository

implementation_dir="$staging_repo/io/github/w296488320/dex-cfg-obfuscator/$version"
marker_dir="$staging_repo/io/github/w296488320/dexcfgobf/io.github.w296488320.dexcfgobf.gradle.plugin/$version"
implementation_jar="$implementation_dir/dex-cfg-obfuscator-$version.jar"
marker_pom="$marker_dir/io.github.w296488320.dexcfgobf.gradle.plugin-$version.pom"

for required_artifact in "$implementation_jar" "$marker_pom"; do
    if [[ ! -s "$required_artifact" ]]; then
        echo "发布校验失败，Maven 文件不存在或为空：$required_artifact" >&2
        exit 1
    fi
done

echo "[3/4] 生成仅包含当前版本的可分发 ZIP"
mkdir -p \
    "$package_root/maven-repo/io/github/w296488320/dex-cfg-obfuscator" \
    "$package_root/maven-repo/io/github/w296488320/dexcfgobf/io.github.w296488320.dexcfgobf.gradle.plugin" \
    "$package_root/doc"
cp -R -- "$implementation_dir" \
    "$package_root/maven-repo/io/github/w296488320/dex-cfg-obfuscator/"
cp -R -- "$marker_dir" \
    "$package_root/maven-repo/io/github/w296488320/dexcfgobf/io.github.w296488320.dexcfgobf.gradle.plugin/"
cp -- "$script_dir/README.md" "$package_root/README.md"
cp -- "$script_dir/doc/README_CN.md" "$package_root/doc/README_CN.md"
cp -- "$script_dir/doc/README_EN.md" "$package_root/doc/README_EN.md"
cp -- "$script_dir/LICENSE" "$package_root/LICENSE"
cp -- "$script_dir/THIRD_PARTY_NOTICES.md" "$package_root/THIRD_PARTY_NOTICES.md"

if find "$package_root" -name .DS_Store -print -quit | grep -q .; then
    echo "发布校验失败：暂存目录中出现 .DS_Store。" >&2
    exit 1
fi

# An exact-tag retry must reproduce the same bytes so the immutable GitHub Release gate can
# distinguish a safe retry from a changed artifact. JAR/ZIP entry order follows the deterministic
# staging layout above; a fixed entry timestamp removes the remaining filesystem-time variance.
jar --create --file "$temporary_archive" --date=2000-01-01T00:00:00Z -C "$package_root" .
archive_entries="$(jar --list --file "$temporary_archive")"
for required_entry in \
    "maven-repo/io/github/w296488320/dex-cfg-obfuscator/$version/dex-cfg-obfuscator-$version.jar" \
    "maven-repo/io/github/w296488320/dexcfgobf/io.github.w296488320.dexcfgobf.gradle.plugin/$version/io.github.w296488320.dexcfgobf.gradle.plugin-$version.pom" \
    "README.md" \
    "doc/README_CN.md" \
    "doc/README_EN.md" \
    "LICENSE" \
    "THIRD_PARTY_NOTICES.md"; do
    if ! grep -Fqx "$required_entry" <<< "$archive_entries"; then
        echo "发布校验失败，ZIP 缺少：$required_entry" >&2
        exit 1
    fi
done
if grep -Fq ".DS_Store" <<< "$archive_entries"; then
    echo "发布校验失败：ZIP 中包含 .DS_Store。" >&2
    exit 1
fi

mkdir -p "$release_dir"
for immutable_target in "$archive" "$checksum"; do
    if [[ -e "$immutable_target" ]]; then
        echo "拒绝覆盖并发创建的发布目标：$immutable_target" >&2
        exit 1
    fi
done
mv -- "$temporary_archive" "$archive"
archive_created=true

if command -v shasum >/dev/null 2>&1; then
    (cd "$release_dir" && shasum -a 256 "$(basename "$archive")") > "$checksum"
else
    (cd "$release_dir" && sha256sum "$(basename "$archive")") > "$checksum"
fi

echo "[4/4] 完成"
echo "版本：$version"
echo "发布包：$archive"
echo "校验值：$checksum"
echo "该 ZIP 可作为 GitHub Release 附件；解压后将 pluginManagement 仓库指向 maven-repo/。"
