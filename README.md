# DexCfgObfuscator

[简体中文](doc/README_CN.md) | [English](doc/README_EN.md)

DexCfgObfuscator is a local Android Gradle plugin that transforms DEX control flow after D8/R8
and before APK packaging. It combines multi-region control-flow flattening, verifier-aware fallback
reordering, original-switch padding, payload relocation, structural verification, safety budgets,
and JSON coverage reports.

DexCfgObfuscator 是一个纯本地 Android Gradle 插件，在 D8/R8 生成 DEX 后、APK 打包前改写
指定业务类的控制流。它组合了多区域控制流平坦化、verifier 感知的安全回退重排、原始 switch
填充、payload 重定位、结构验证、体积预算和 JSON 覆盖报告。

> This project raises the cost of static analysis. It is not encryption and cannot guarantee that
> code will never be understood by a human, AI system, or decompiler.
>
> 本项目用于提高静态分析成本，不是加密，也不能保证代码永远无法被人工、AI 或反编译器理解。

## Documentation / 文档

- [中文完整文档](doc/README_CN.md)
- [Full English documentation](doc/README_EN.md)

## Highlights / 主要能力

- Runs on Android application variants and supports both debug D8 output and release R8 output.
- Resolves configured source class prefixes through `mapping.txt` after R8.
- Uses 2–4 independent sparse-switch dispatcher regions according to the selected level.
- Stores dispatcher state as two XOR shares and reconstructs it only for short-lived dispatch work.
- Adds reachable equivalent alias/trampoline paths instead of relying only on dead branches.
- Encodes and pads original switch keys with random 32-bit keys and visible character cases.
- Relocates `fill-array-data`, packed-switch, and sparse-switch payloads on safe reorder paths.
- Preserves/rebuilds try ranges and catch handlers on supported transformations.
- Re-parses staged DEX files and verifies registers, branches, payloads, handlers, and try ranges.
- Falls back conservatively when verifier analysis, register formats, or post-transform budgets fail.
- Writes one machine-readable coverage report for every processed variant.
- Performs all transformations locally; the plugin does not upload source code or DEX files.

## Coordinates / 坐标

| Item | Value |
|---|---|
| Plugin ID | `com.hunter.dexcfgobf` |
| Implementation group | `com.hunter` |
| Current version | `0.0.4` |
| Java baseline | Java 17 |
| Development baseline | Gradle 9.6.1, AGP 9.3.1 |
| Artifact type | Gradle plugin JAR distributed through a Maven repository |

## Quick start / 快速接入

Download or build the Maven-repository ZIP, extract it, and point the consuming build at the
included `maven-repo/` directory.

下载或生成 Maven 仓库 ZIP，解压后让宿主项目指向其中的 `maven-repo/` 目录。

`settings.gradle`:

```groovy
pluginManagement {
    repositories {
        maven { url = uri("../DexCfgObfuscator/maven-repo") }
        gradlePluginPortal()
        google()
        mavenCentral()
    }
}
```

Android application module `build.gradle`:

```groovy
import com.hunter.dexcfgobf.gradle.ObfuscationLevel

plugins {
    id 'com.android.application'
    id 'com.hunter.dexcfgobf' version '0.0.4'
}

dexControlFlowObfuscator {
    enabled true
    level ObfuscationLevel.MEDIUM
    obfClass = ['com.example.app']
    blackClass = ['com.example.app.bootstrap']
}
```

Build from a pristine producer DEX while the current AGP adapter still uses an in-place post-D8/R8
integration:

```bash
./gradlew :app:assembleRelease --rerun-tasks
```

The report is written to:

```text
app/build/reports/dex-cfg-obfuscator/<variant>.json
```

## Build and distribute / 构建与分发

```bash
cd DexCfgObfuscator
./build-release.sh
```

The script runs tests and plugin validation, publishes the local Maven repository, and creates:

```text
release/dex-cfg-obfuscator-<version>-maven-repo.zip
release/dex-cfg-obfuscator-<version>-maven-repo.zip.sha256
```

## Important limitations / 重要限制

- The current public AGP API does not expose a stable post-R8 DEX transform artifact for this
  integration. Version `0.0.4` locates the DEX-producing task and modifies its output after staging
  verification.
- Reusing an already modified producer directory in an incremental build can cause original-switch
  padding to be seen again. Use a clean build or `--rerun-tasks` for reproducible release builds.
- Decompiler rendering is not an API. A character switch may still be displayed as decimal integers.
- Some register encodings, wide/range instructions, monitor operations, verifier-ambiguous methods,
  or very large methods are deliberately reordered or skipped.
- Always test release artifacts on the Android versions and devices supported by the application.

See the language-specific documentation for the complete integration guide, architecture,
configuration reference, report schema, validation workflow, and troubleshooting information.

## License / 许可证

No `LICENSE` file has been selected yet. Add the license chosen by the project owner before the
public release. / 当前尚未选择并加入 `LICENSE` 文件，正式公开发布前需要由项目所有者确定许可证。
