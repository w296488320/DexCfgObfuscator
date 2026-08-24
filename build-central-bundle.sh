#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
gradlew="$script_dir/gradlew"

is_true() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|on|ON) return 0 ;;
        *) return 1 ;;
    esac
}

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
                echo "缺少 MD5 工具：需要 md5sum 或 md5。" >&2
                return 1
            fi
            ;;
        sha1)
            if command -v sha1sum >/dev/null 2>&1; then
                sha1sum "$input_file" | awk '{print $1}'
            elif command -v shasum >/dev/null 2>&1; then
                shasum -a 1 "$input_file" | awk '{print $1}'
            else
                echo "缺少 SHA-1 工具：需要 sha1sum 或 shasum。" >&2
                return 1
            fi
            ;;
        *)
            echo "未知摘要算法：$algorithm" >&2
            return 1
            ;;
    esac
}

for command_name in jar zip; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "缺少必需命令：$command_name" >&2
        exit 1
    fi
done

if command -v shasum >/dev/null 2>&1; then
    sha256_command=(shasum -a 256)
elif command -v sha256sum >/dev/null 2>&1; then
    sha256_command=(sha256sum)
else
    echo "缺少 SHA-256 工具：需要 shasum 或 sha256sum。" >&2
    exit 1
fi

coordinate_output="$("$gradlew" -q printMavenCentralCoordinates \
    --no-daemon --no-configuration-cache)"
group_id="$(sed -n 's/^group=//p' <<<"$coordinate_output" | tail -n 1)"
artifact_id="$(sed -n 's/^artifact=//p' <<<"$coordinate_output" | tail -n 1)"
version="$(sed -n 's/^version=//p' <<<"$coordinate_output" | tail -n 1)"
plugin_id="$(sed -n 's/^pluginId=//p' <<<"$coordinate_output" | tail -n 1)"

if [[ -z "$group_id" || -z "$artifact_id" || -z "$version" || -z "$plugin_id" ]]; then
    echo "无法从 Gradle 读取完整的 Maven Central 坐标。" >&2
    exit 1
fi
if [[ "$version" =~ -[Ss][Nn][Aa][Pp][Ss][Hh][Oo][Tt]$ ]]; then
    echo "Maven Central bundle 不能使用 SNAPSHOT 版本：$version" >&2
    exit 1
fi

central_namespace="${MAVEN_CENTRAL_NAMESPACE:-$group_id}"
if [[ "$group_id" != "$central_namespace" && "$group_id" != "$central_namespace".* ]]; then
    echo "groupId 不属于已声明的 Central namespace：$group_id / $central_namespace" >&2
    exit 1
fi
if [[ "$plugin_id" != "$central_namespace" && "$plugin_id" != "$central_namespace".* ]]; then
    echo "plugin marker group 不属于已声明的 Central namespace：$plugin_id / $central_namespace" >&2
    exit 1
fi

central_preview=false
if is_true "${DEXCFG_CENTRAL_PREVIEW:-false}"; then
    central_preview=true
    echo "警告：DEXCFG_CENTRAL_PREVIEW=true，仅生成本地预演包；不得上传该产物。" >&2
else
    if ! git -C "$script_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        echo "正式 Central bundle 必须从 Git 工作树生成。" >&2
        echo "仅本地预演可显式设置 DEXCFG_CENTRAL_PREVIEW=true。" >&2
        exit 1
    fi
    dirty_files="$(git -C "$script_dir" status --porcelain --untracked-files=all -- .)"
    if [[ -n "$dirty_files" ]]; then
        echo "正式 Central bundle 要求工作树干净；当前仍有以下改动：" >&2
        printf '%s\n' "$dirty_files" >&2
        echo "请先提交，或仅预演时设置 DEXCFG_CENTRAL_PREVIEW=true。" >&2
        exit 1
    fi
    if ! git -C "$script_dir" tag --points-at HEAD | grep -Fqx "v$version"; then
        echo "正式 Central bundle 要求 HEAD 带有精确版本 tag：v$version" >&2
        echo "请在审核提交后创建 tag，或仅预演时设置 DEXCFG_CENTRAL_PREVIEW=true。" >&2
        exit 1
    fi
fi

release_dir="$script_dir/release"
archive="${CENTRAL_BUNDLE_OUTPUT:-$release_dir/$artifact_id-$version-central-bundle.zip}"
if [[ "$archive" != /* ]]; then
    archive="$script_dir/$archive"
fi
checksum="$archive.sha256"

if [[ -e "$archive" || -e "$checksum" ]]; then
    echo "拒绝覆盖已有 Central bundle：$archive" >&2
    echo "请提升版本，或显式设置一个不存在的 CENTRAL_BUNDLE_OUTPUT。" >&2
    exit 1
fi

mkdir -p "$(dirname "$archive")"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/dexcfg-central.XXXXXX")"
staging_dir="$work_dir/repository"
mkdir -p "$staging_dir"

cleanup() {
    local status=$?
    trap - EXIT
    if [[ -d "$work_dir" ]]; then
        rm -rf -- "$work_dir"
    fi
    exit "$status"
}
trap cleanup EXIT

echo "[1/4] 测试并生成已签名 Maven Central publication"
"$gradlew" test validatePlugins publishAllPublicationsToCentralBundleRepository \
    -PcentralBundleRepo="$staging_dir" \
    --no-daemon --no-configuration-cache

group_path="$(tr '.' '/' <<<"$group_id")"
plugin_path="$(tr '.' '/' <<<"$plugin_id")"
implementation_dir="$staging_dir/$group_path/$artifact_id/$version"
marker_artifact="$plugin_id.gradle.plugin"
marker_dir="$staging_dir/$plugin_path/$marker_artifact/$version"

required_files=(
    "$implementation_dir/$artifact_id-$version.jar"
    "$implementation_dir/$artifact_id-$version-sources.jar"
    "$implementation_dir/$artifact_id-$version-javadoc.jar"
    "$implementation_dir/$artifact_id-$version.pom"
    "$marker_dir/$marker_artifact-$version.pom"
)

for required_file in "${required_files[@]}"; do
    if [[ ! -s "$required_file" ]]; then
        echo "Central bundle 缺少发布文件：$required_file" >&2
        exit 1
    fi
done

echo "[2/4] 校验 POM、许可证和校验和，并检查签名文件"
for pom_file in "$implementation_dir/$artifact_id-$version.pom" \
                "$marker_dir/$marker_artifact-$version.pom"; do
    for element in name description url licenses developers scm; do
        if ! grep -Fq "<$element>" "$pom_file"; then
            echo "POM 缺少 Maven Central 元数据 <$element>：$pom_file" >&2
            exit 1
        fi
    done
done

if ! jar tf "$implementation_dir/$artifact_id-$version.jar" \
        | grep -Eq '^META-INF/LICENSE(\..*)?$'; then
    echo "实现 JAR 未包含 META-INF/LICENSE。" >&2
    exit 1
fi

while IFS= read -r -d '' published_file; do
    if [[ ! -s "$published_file.asc" ]]; then
        echo "发布文件缺少 detached PGP signature：$published_file" >&2
        exit 1
    fi
    for algorithm in md5 sha1; do
        checksum_file="$published_file.$algorithm"
        if [[ ! -s "$checksum_file" ]]; then
            echo "发布文件缺少 .$algorithm：$published_file" >&2
            exit 1
        fi
        expected_digest="$(tr -d '[:space:]' < "$checksum_file")"
        actual_digest="$(digest_file "$algorithm" "$published_file")"
        if [[ "$expected_digest" != "$actual_digest" ]]; then
            echo "发布文件 .$algorithm 校验失败：$published_file" >&2
            exit 1
        fi
    done
done < <(find "$implementation_dir" "$marker_dir" -type f \
    \( -name '*.jar' -o -name '*.pom' -o -name '*.module' \) -print0)

echo "[3/4] 生成仅包含当前版本的 Maven-layout ZIP"
(
    cd "$staging_dir"
    zip -q -r "$archive" . \
        -x '*/.DS_Store' '*/maven-metadata.xml' '*/maven-metadata.xml.*' \
           '*.asc.md5' '*.asc.sha1' '*.asc.sha256' '*.asc.sha512'
)

echo "[4/4] 生成 SHA-256"
(
    cd "$(dirname "$archive")"
    "${sha256_command[@]}" "$(basename "$archive")" > "$(basename "$checksum")"
)

echo "Maven Central bundle 已生成（尚未上传，也尚未发布）："
echo "  $archive"
echo "  $checksum"
if [[ "$central_preview" == true ]]; then
    echo "这是未提交/未打 tag 的本地预演产物，不得上传；正式发布时不要设置 DEXCFG_CENTRAL_PREVIEW。"
else
    echo "下一步：登录 https://central.sonatype.com/，手工上传 ZIP 并在校验通过后确认 Publish。"
fi
