# DexCfgObfuscator

[简体中文](doc/README_CN.md) | [English](doc/README_EN.md)

DexCfgObfuscator is a local Android Gradle plugin that encrypts executable JVM string literals before
D8/R8 and transforms DEX control flow after D8/R8. It combines a pluggable string cipher/key SPI,
multi-region control-flow flattening, verifier-aware fallback reordering, payload relocation,
structural verification, safety budgets, and JSON coverage reports.

DexCfgObfuscator 是一个纯本地 Android Gradle 插件：在 D8/R8 前加密可执行字符串字面量，
在 D8/R8 后、APK 打包前改写指定业务类的 DEX 控制流。它提供可插拔算法/密钥 SPI，并组合
多区域控制流平坦化、verifier 感知的安全回退、payload 重定位、结构验证和 JSON 报告。

> This project raises the cost of static analysis. Embedded keys and runtime plaintext mean the
> string stage is not secret storage, and no obfuscator can prevent determined runtime analysis.
>
> 本项目用于提高静态分析成本。密钥仍随 APK 分发、明文必然在运行期出现，因此它不是秘密存储，
> 也不能阻止有针对性的动态分析。

## Documentation / 文档

- [中文完整文档](doc/README_CN.md)
- [Full English documentation](doc/README_EN.md)

## Highlights / 主要能力

- Runs the application string stage with `ALL` scope, so configured package prefixes cover matching
  classes from the app and its dependency graph; library variants use `PROJECT` scope. Final DEX CFG
  processing remains application-only.
- Replaces method literals and `static final String` ConstantValue entries before D8/R8.
- Before packaging a library AAR, rebuilds modified classes with a fresh constant pool and scans
  every discovered project class/JAR class entry for tracked plaintext by SHA-256.
- Provides a built-in per-site key/stream transform and reflection-compatible custom cipher/key contracts.
- Resolves configured source class prefixes through `mapping.txt` after R8.
- Uses 2–4 independent sparse-switch dispatcher regions according to the selected level.
- Stores dispatcher state as two XOR shares and reconstructs it only for short-lived dispatch work.
- Adds reachable equivalent alias/trampoline paths instead of relying only on dead branches.
- Encodes and pads original switch keys with random 32-bit keys and visible character cases.
- Relocates `fill-array-data`, packed-switch, and sparse-switch payloads on safe reorder paths.
- Preserves/rebuilds try ranges and catch handlers on supported transformations.
- Re-parses staged DEX files and verifies registers, branches, payloads, handlers, and try ranges.
- Falls back conservatively when verifier analysis, register formats, or post-transform budgets fail.
- Scans final application DEX runtime string payloads and fails when plaintext selected for
  encryption is still executable or reflectively readable; whole-pool matches remain diagnostic so
  class/member/debug names do not become false leak failures. Schema-10 reports bind proof/leak counts
  to artifact and transform fingerprints.
- Persists checksummed incremental evidence (including tracked plaintext hashes and original member
  scopes) under `build/intermediates` so cached builds re-run gates instead of bypassing them. The
  plugin does not emit those hashes into schema-10 JSON or APK metadata; local evidence must not be
  distributed.
- Exposes CFG/string coverage and size gates for release CI, including string-only application builds.
- Performs all transformations locally; the plugin does not upload source code or DEX files.

## Coordinates / 坐标

| Item | Value |
|---|---|
| Plugin ID | `com.hunter.dexcfgobf` |
| Implementation group | `com.hunter` |
| Current version | `0.0.14` |
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
import com.hunter.dexcfgobf.string.StringEncryptionMode

plugins {
    id 'com.android.application'
    id 'com.hunter.dexcfgobf' version '0.0.14'
}

dexControlFlowObfuscator {
    enabled true
    enabledVariants = ['release'] // CFG only; the string stage remains independent
    level ObfuscationLevel.MEDIUM
    obfClass = ['com.example.app']
    blackClass = ['com.example.app.bootstrap']
    minObfuscatedMethods = 20
    minFlattenedMethods = 10 // reordered methods do not satisfy this gate
    minObfuscatedRatio = 0.30
    maxSizeIncreasePercent = 50

    stringEncryption {
        enabled true
        mode StringEncryptionMode.BYTES
        packages = ['com.example.app', 'com.example.feature']
        excludePackages = ['com.example.app.databinding']
    }
}
```

These four string-encryption options are sufficient for normal use. Safety, plaintext-leak,
decryptor-protection, final-DEX, and coverage gates use secure defaults. Application variants inspect
matching classes across the complete dependency graph automatically; no dependency-evidence project
list is required. Run release builds with `--rerun-tasks` so the default release coverage gate can
prove a complete fresh visit.

Build from a pristine producer DEX while the current AGP adapter still uses an in-place post-D8/R8
integration:

```bash
./gradlew :app:assembleRelease --rerun-tasks --no-configuration-cache
```

The report is written to:

```text
app/build/reports/dex-cfg-obfuscator/<variant>.json
```

Android application variants use `ALL` scope for string encryption: every app, project-library, and
external-library class whose name matches `packages` and not `excludePackages` is eligible without
extra per-dependency configuration. Android library modules may also apply the plugin when publishing
a protected standalone AAR; library variants use `PROJECT` scope and only their pre-D8/R8 string stage
runs. Before AAR packaging, the plugin compacts transformed project classes and scans their JVM runtime
String payloads. A library-only build still cannot prove plaintext absence from a consuming app's
final APK/AAB, so release CI should run the consuming application's final-DEX gate.

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
  integration. Version `0.0.14` locates the DEX-producing task and modifies its output after staging
  verification.
- Version `0.0.14` supports both `mergeProjectDex<Variant>` and application task graphs that expose
  only `mergeDex<Variant>`; explicit package filters still prevent dependency classes from being
  transformed unintentionally.
- Version `0.0.14` binds each successfully transformed DEX directory to checksummed CFG statistics,
  transform configuration, and artifact fingerprints. Cached builds restore those statistics and
  re-run all gates; an OS file lock serializes each DEX transaction, while a pre-transform
  transaction marker detects interrupted evidence commits.
  Missing/corrupt/mismatched evidence fails closed instead of trusting an old report or rewriting an
  already-obfuscated DEX. The four CFG quality budgets are evaluated once on variant-aggregate
  current/cached statistics after the schema-10 report is refreshed. Before any fresh CFG rewrite,
  a variant-wide transaction snapshots every candidate DEX and writable evidence/state/report file;
  any caught later gate or evidence failure restores the complete pre-task artifact set. An abrupt
  process termination remains fail-closed through the pre-transform transaction marker.
- Version `0.0.14` reads the DEX header and selects the matching opcode table, including `dex.039`
  `invoke-polymorphic`/`invoke-custom`, instead of forcing the legacy API 20 table.
- Decompiler rendering is not an API. A character switch may still be displayed as decimal integers.
- Some register encodings, wide/range instructions, monitor operations, verifier-ambiguous methods,
  or very large methods are deliberately reordered or skipped.
- String encryption covers JVM `LDC` literals and supported constant fields in matching app and
  dependency-graph classes, not resources, manifests, native strings, annotation/metadata values, or
  every string that R8 may
  synthesize later. Unsupported executable bootstrap strings and non-structural dynamic call-site
  names fail closed by default instead of being silently exposed. Exact javac concat, lambda, and
  record call-site names are accepted only after their complete compiler shape is validated; exact
  `ObjectMethods.bootstrap` record component-name metadata is likewise treated as structural metadata
  rather than protected business text. Every `ConstantDynamic` name remains unsupported. The
  application gate also checks recursively encoded annotation and call-site names/arguments when they
  equal tracked protected text; metadata-only text is not registered or rewritten.
- The application and library gates fail on matching runtime payloads. Application payloads include
  `const-string`, static String values, annotation values, and referenced non-structural call-site
  names/arguments; library payloads include JVM LDC/ConstantValue, annotation values, and
  invokedynamic/condy String names/arguments. Both still report whole-pool collisions for diagnostics, and
  `strictWholeStringPool=true` restores conservative artifact-wide value absence. Set
  `failOnPlaintextLeak=false` only when explicitly accepting a warning-only bypass. Application
  builds record effective leaks in schema-10 JSON; library builds keep equivalent local evidence but
  do not emit that application report.
- Library compaction recursively discovers class files and class JARs below the AGP transform output
  roots and scans direct class entries in each JAR. It does not recursively unpack archives embedded
  as JAR resources. A modified class with an unknown ASM attribute cannot be compacted safely, and the
  semantic verifier also refuses unknown attributes in any scanned class because they may hide JVM
  payloads or stale constant-pool indexes. A signed class JAR that would need rewriting is refused and
  left unchanged because rewriting would invalidate its `META-INF` signatures.
- Removing a public `static final String` ConstantValue preserves the field descriptor but changes
  Java source/compile-time-constant ABI. Consumer annotation attributes or `case` labels may stop
  compiling, while consumers built against an older/untransformed API may retain an inlined plaintext
  copy. Exclude such API constants or move them to an unprotected API module and run consumer builds.
- Protected `static final String` values are assigned at the beginning of `<clinit>`. A custom
  decryptor must not re-enter that business class and read another protected static field before its
  assignment; same-thread JVM initialization re-entry can observe the default value. The built-in
  decryptor keeps a one-way dependency and does not re-enter business classes.
- `BYTES` dry-runs the complete JVM method before writing it. If its conservative 65,535-byte Code
  budget is exceeded, that whole method uses `BASE64`; the transform fails before class emission if
  the all-BASE64 plan also exceeds the limit. It never emits a partially mixed method.
- The string stage currently requires `--no-configuration-cache` when enabled.
- Enabling this string stage while the old `stringfog` plugin is applied fails fast to prevent
  double instrumentation. Nested `stringFog {}` / `stringfog {}` are only migration aliases inside
  `dexControlFlowObfuscator`; it is not the old top-level extension.
- Schema-10 JSON is emitted for application CFG and application string-only builds. Library variants
  do not emit that application report; they use separate checksummed evidence bound to the transform
  class artifact and string configuration, then run their class-pool gate before AAR packaging. A
  buildDir-wide OS lock is acquired before library `clean`/Android build work and released only after
  all scheduled build work finishes; a second process sharing that buildDir fails fast.
- Incremental string evidence stores SHA-256 values (never plaintext) below `build/intermediates`.
  These hashes can reveal short/common strings by dictionary attack to someone who already has the
  local build directory; `clean` removes them, and they must never be committed or distributed.
  A partial incremental visit conservatively unions compatible prior hashes with current hashes;
  configuration changes require a clean/rerun proof, while `--rerun-tasks` resets the union as a full
  snapshot. The secure defaults require known complete coverage for release variants; use
  `--rerun-tasks` in release CI because a first partial build without prior evidence cannot prove full
  coverage. Advanced gate properties remain available for exceptional compatibility migrations but
  are not required in normal configuration.
- Dynamic-feature modules are not yet instrumented/audited end-to-end. With the default strict
  plaintext gate, configuring `dynamicFeatures` is rejected instead of claiming whole-bundle proof;
  report-only mode warns and keeps coverage non-FULL.
- Always test release artifacts on the Android versions and devices supported by the application.
- JADX can recover the generated bridge, ciphertext/key carriers, and built-in algorithm well enough
  for an analyst to write an offline decoder without running the app. Treat removal of immediate
  plaintext and higher recovery cost as the result, not cryptographic secrecy or irrecoverability.

See the language-specific documentation for the complete integration guide, architecture,
configuration reference, report schema, validation workflow, and troubleshooting information.

## License / 许可证

No `LICENSE` file has been selected yet. Add the license chosen by the project owner before the
public release. / 当前尚未选择并加入 `LICENSE` 文件，正式公开发布前需要由项目所有者确定许可证。
