# DexCfgObfuscator

[简体中文](doc/README_CN.md) | [English](doc/README_EN.md)

DexCfgObfuscator is an Android Gradle plugin that performs all processing inside the consuming build:
it encrypts executable JVM string literals before D8/R8 and transforms DEX control flow after D8/R8.
It combines a pluggable string cipher/key SPI,
multi-region control-flow flattening, verifier-aware fallback reordering, payload relocation,
structural verification, safety budgets, and JSON coverage reports.

DexCfgObfuscator 是一个在宿主构建过程中完成全部处理的 Android Gradle 插件：在 D8/R8 前加密
可执行字符串字面量，在 D8/R8 后、APK 打包前改写指定业务类的 DEX 控制流。它提供可插拔算法/
密钥 SPI，并组合多区域控制流平坦化、verifier 感知的安全回退、payload 重定位、结构验证和
JSON 报告。

> This project raises the cost of static analysis. Embedded keys and runtime plaintext mean the
> string stage is not secret storage, and no obfuscator can prevent determined runtime analysis.
>
> 本项目用于提高静态分析成本。密钥仍随 APK 分发、明文必然在运行期出现，因此它不是秘密存储，
> 也不能阻止有针对性的动态分析。

## Documentation / 文档

- [中文完整文档](doc/README_CN.md)
- [Full English documentation](doc/README_EN.md)
- [Public repository publishing guide / 在线仓库发布指南](doc/MAVEN_CENTRAL.md)
- [Android consumer sample](samples/android-consumer)
- [Contributing](CONTRIBUTING.md) | [Security policy](SECURITY.md) | [Changelog](CHANGELOG.md)

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
- Since `0.1.1`, the plugin preserves the minimum DEX line-number program required for crash
  diagnosis and registers a `retrace<Variant>DexCfgStackTrace` task for build-matched R8 retracing.
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
| Plugin ID | `io.github.w296488320.dexcfgobf` |
| Implementation group | `io.github.w296488320` |
| Current version | `0.1.2` |
| Java baseline | Java 17 |
| Development baseline | Gradle 9.6.1, AGP 9.3.1 |
| Artifact type | Gradle plugin JAR distributed through a Maven repository |

> **Version boundary:** stack-trace line preservation and the retrace task are available in
> `0.1.1`. APKs built with `0.1.0` do not gain missing CFG line positions retroactively, and the
> published `0.1.0` bytes remain immutable. / **版本边界：** 行号保留与 retrace task 从 `0.1.1`
> 开始提供；使用 `0.1.0` 构建的 APK 不会被事后补回已经丢失的 CFG 行号，已发布的 `0.1.0`
> 制品仍保持不可变。

The checked-in Android sample verifies string-only, CFG-only, combined, and R8-enabled Release APK
builds on this baseline. Other Gradle/AGP versions, AAB, dynamic features, and OEM runtime behavior
remain unverified unless stated otherwise. / 仓库内示例已验证上述基线下的字符串单开、CFG 单开、双开和
R8 Release APK；其他 Gradle/AGP、AAB、dynamic feature 与 OEM 运行行为不作未经测试的兼容承诺。

## Online quick start / 在线仓库快速接入

Tagged releases are published as a complete Maven repository on GitHub Pages. It is anonymous,
preserves both the implementation component and Gradle plugin marker, and does not require consumers
to download or build this repository. Gradle Plugin Portal and Maven Central use the same canonical
plugin ID when those mirrors become available. / 正式 tag 会把完整 Maven 仓库发布到 GitHub Pages；
使用者无需账号，也无需下载或自行构建本仓库。Gradle Plugin Portal 与 Maven Central 上线后仍使用
同一个 canonical plugin ID。

`settings.gradle`:

```groovy
pluginManagement {
    repositories {
        maven {
            name = 'DexCfgObfuscatorGitHubPages'
            url = uri('https://w296488320.github.io/DexCfgObfuscator/maven-repo')
            content {
                includeGroupByRegex 'io\\.github\\.w296488320(\\..*)?'
            }
        }
        google()
        gradlePluginPortal()
        mavenCentral()
    }
}
```

Root project `build.gradle` / 项目根 `build.gradle`：

```groovy
plugins {
    // Keep existing Android/Kotlin declarations and add this line.
    // 保留已有 Android/Kotlin 插件声明，只增加这一行。
    id 'io.github.w296488320.dexcfgobf' version '0.1.2' apply false
}
```

Android application module `build.gradle` / application 模块 `build.gradle`：

```groovy
import com.hunter.dexcfgobf.gradle.ObfuscationLevel
import com.hunter.dexcfgobf.string.StringEncryptionMode

plugins {
    id 'com.android.application'
    id 'io.github.w296488320.dexcfgobf'
}

dexControlFlowObfuscator {
    dexObfuscator {
        enabled true
        level ObfuscationLevel.MEDIUM
        obfClass = ['com.example.app']
        blackClass = ['com.example.app.bootstrap']
    }

    stringEncryption {
        enabled true
        mode StringEncryptionMode.BYTES
        packages = ['com.example.app', 'com.example.feature']
        excludePackages = ['com.example.app.databinding']
    }
}
```

If the root project does not manage plugin versions, put `version '0.1.2'` on the module plugin line
instead; use exactly one version-management style. / 如果根项目不统一管理插件版本，才在模块插件 ID
后追加 `version '0.1.2'`；两种方式选择一种即可。

### Offline fallback / 离线备用

For offline/internal distribution, download the matching GitHub Release Maven-repository ZIP,
extract it, and add its `maven-repo/` directory before the remote repositories in
`pluginManagement`. / 离线或内部分发可下载同版本 GitHub Release Maven 仓库 ZIP，解压后把其中的
`maven-repo/` 放在 `pluginManagement` 远程仓库之前。

`dexControlFlowObfuscator {}` is the container for independent protection modules. Enable or disable
`dexObfuscator {}` and `stringEncryption {}` separately. Version `0.1.0` removes the CFG
`enabledVariants` selector from the canonical DSL; the consumer decides whether to enable the CFG
module. Additional CFG quality budgets remain available in the detailed documentation.

Starting with `0.1.2`, `stringEncryption.enabled` and a non-empty
`stringEncryption.enabledVariants` selector use OR semantics. Set `enabled true` to enable every
variant, or leave it `false` and select exact variant/build-type names. An empty selector alone keeps
the default disabled state; `enabled true` combined with a selector still enables every variant. /
从 `0.1.2` 起，`stringEncryption.enabled` 与非空 `enabledVariants` 使用 OR 语义：可用
`enabled true` 启用全部 variant，也可保持 `false` 并按精确 variant/buildType 选择。空列表本身
不会启用字符串阶段；`enabled true` 与 selector 同时配置时仍然是全部启用。

Do not consume version `0.0.16`. Version `0.1.0` fixes the nested mutation callback when Gradle
decorates the real extension instance; without that fix, nested module configuration can fail during
consumer project configuration.

These four string-encryption options are sufficient for normal use. Safety, plaintext-leak,
decryptor-protection, final-DEX, and coverage gates use secure defaults. Application variants inspect
matching classes across the complete dependency graph automatically; no dependency-evidence project
list is required. A normal release build automatically forces and verifies a complete ASM visit;
callers do not need to add `--rerun-tasks` for the default strict coverage gate.

Build from a pristine producer DEX while the current AGP adapter still uses an in-place post-D8/R8
integration:

```bash
./gradlew :app:assembleRelease --no-configuration-cache
```

The report is written to:

```text
app/build/reports/dex-cfg-obfuscator/<variant>.json
```

The following workflow requires plugin `0.1.1` or later; the published `0.1.0` plugin does not
register this task. Install Android SDK Command-line Tools and
ensure its `retrace` executable is available first. CFG changes instruction layout inside a method,
but it does not add, remove, or rename Java call frames. The transform therefore keeps the minimum
valid `LineNumber` information already present in its input DEX; it cannot invent a missing source
position. For an R8-minified release, retrace a crash with the task generated for that same variant:

```bash
./gradlew :app:retraceReleaseDexCfgStackTrace \
  --trace-file=/absolute/path/crash.txt \
  --output-file=/absolute/path/crash.retraced.txt \
  --mapping-file=/private/archive/that-release/mapping.txt
```

`--trace-file` is required; `--output-file` and `--mapping-file` are optional. Without an output
option, the task inserts `.retraced` before the input extension (`crash.txt` becomes
`crash.retraced.txt`); a name without an extension receives `.retraced.txt`. A non-minified variant
is copied unchanged because its CFG stack frames already retain source lines. A minified variant
requires the unmodified R8 `mapping.txt` produced by the same build; no second CFG mapping is needed.
The task does not prove that an archived mapping belongs to a crash, so bind APK/AAB, version/build
identity, APK hash, and mapping in private release storage. Omit `--mapping-file` only for a
just-built, confirmed-matching variant in the current checkout. The task never rebuilds or changes
an APK and never uploads the mapping or trace.

这套流程需要 `0.1.1` 或更高版本；`0.1.0` 不会注册该任务。
请先安装 Android SDK Command-line Tools 并确认其中的 `retrace` 可执行。CFG 只改变方法内部指令
布局，默认保留输入 DEX 中已有且有效的最小 residual line，不会凭空生成缺失源码位置；R8 日志
继续使用同一次构建且未修改的原始
`mapping.txt`，不需要也不应生成第二份 CFG mapping。任务不会自动证明归档 mapping 与线上 APK
匹配，发布系统应私密绑定版本/build identity、APK 哈希和 mapping。详细说明见
[中文第 7 步](doc/README_CN.md#第-7-步还原线上崩溃栈)与
[English Step 7](doc/README_EN.md#step-7-retrace-a-production-crash)。

Android application variants use `ALL` scope for string encryption: every app, project-library, and
external-library class whose name matches `packages` and not `excludePackages` is eligible without
extra per-dependency configuration. Android library modules may also apply the plugin when publishing
a protected standalone AAR; library variants use `PROJECT` scope and only their pre-D8/R8 string stage
runs. Before AAR packaging, the plugin compacts transformed project classes and scans their JVM runtime
String payloads. A library-only build still cannot prove plaintext absence from a consuming app's
final APK/AAB, so release CI should run the consuming application's final-DEX gate.

## Build and distribute / 构建与分发

This section is for maintainers and offline/internal distribution. Normal online consumers do not
run these commands. / 本节用于维护者发布以及离线/内部分发；普通在线使用者不执行这些命令。

```bash
cd DexCfgObfuscator
./build-release.sh
```

The script runs tests and plugin validation, publishes into an isolated temporary Maven repository,
and packages only the current immutable version:

```text
release/dex-cfg-obfuscator-<version>-maven-repo.zip
release/dex-cfg-obfuscator-<version>-maven-repo.zip.sha256
```

Pushing an immutable `v<version>` tag runs the GitHub Pages publication workflow. It allows an exact
byte-for-byte retry but refuses a partial or different implementation/marker version, merges the
Maven layout into the persistent `gh-pages` branch, deploys and verifies the public repository, and
attaches the offline ZIP plus SHA-256 to the matching GitHub Release. Published bytes are never
overwritten.

Before the first tag, the maintainer must make the GitHub repository public and select
**Settings → Pages → Source: GitHub Actions**. Then open
**Settings → Environments → github-pages → Deployment branches and tags**, keep the `main` branch
rule, and add a tag rule named `v*`; otherwise the Pages deployment rejects release tags even when
the build and uploaded artifact succeed. The workflow deliberately cannot change repository
visibility, enable Pages, or relax environment deployment rules with its normal `GITHUB_TOKEN`.

The local plugin checks and Portal task graph do not need publishing credentials:

```bash
./gradlew test validatePlugins
./gradlew publishPlugins --validate-only --dry-run
```

Authenticated Portal metadata validation uses `./gradlew publishPlugins --validate-only`; the real
upload uses `./gradlew publishPlugins`. Both require a Gradle Plugin Portal account plus private
`GRADLE_PUBLISH_KEY` and `GRADLE_PUBLISH_SECRET`, and both are independent from Maven Central.

For Maven Central, generate a signed Maven-layout bundle without uploading it:

```bash
./build-central-bundle.sh
```

Formal bundles require a clean checkout whose `HEAD` is tagged `v<version>`; an explicit
`DEXCFG_CENTRAL_PREVIEW=true` mode exists only for local validation and must not be uploaded.
Account, namespace, GPG, and manual Portal upload steps are documented in
[doc/MAVEN_CENTRAL.md](doc/MAVEN_CENTRAL.md). Generated repositories and archives are build outputs;
they are not committed to source control.

## Reproducible Android sample / 可复现 Android 示例

The source-consumer sample covers string-only, CFG-only, both, and R8-enabled release builds without
publishing the plugin first:

```bash
./gradlew -p samples/android-consumer :app:assembleRelease \
  -PsampleProtection=both -PsampleMinify=true --no-configuration-cache
```

See [samples/android-consumer/README.md](samples/android-consumer/README.md) for every mode and the
generated report paths.

## Important limitations / 重要限制

- The current public AGP API does not expose a stable post-R8 DEX transform artifact for this
  integration. Version `0.1.2` locates the DEX-producing task and modifies its output after staging
  verification.
- Version `0.1.2` supports both `mergeProjectDex<Variant>` and application task graphs that expose
  only `mergeDex<Variant>`; explicit package filters still prevent dependency classes from being
  transformed unintentionally.
- Version `0.1.2` binds each successfully transformed DEX directory to checksummed CFG statistics,
  transform configuration, and artifact fingerprints. Cached builds restore those statistics and
  re-run all gates; an OS file lock serializes each DEX transaction, while a pre-transform
  transaction marker detects interrupted evidence commits.
  Missing/corrupt/mismatched evidence fails closed instead of trusting an old report or rewriting an
  already-obfuscated DEX. The four CFG quality budgets are evaluated once on variant-aggregate
  current/cached statistics after the schema-10 report is refreshed. Before any fresh CFG rewrite,
  a variant-wide transaction snapshots every candidate DEX and writable evidence/state/report file;
  any caught later gate or evidence failure restores the complete pre-task artifact set. An abrupt
  process termination remains fail-closed through the pre-transform transaction marker.
- Version `0.1.2` reads the DEX header and selects the matching opcode table, including `dex.039`
  `invoke-polymorphic`/`invoke-custom`, instead of forcing the legacy API 20 table.
- Decompiler rendering is not an API. A character switch may still be displayed as decimal integers.
- Some register encodings, wide/range instructions, monitor operations, verifier-ambiguous methods,
  or very large methods are deliberately reordered or skipped.
- A historical `Unknown Source` frame with neither a line number nor a DEX PC cannot be reconstructed
  after the fact. A single stack trace records call frames, not every branch taken inside a method,
  so retracing restores source call-stack context rather than the complete dynamic control-flow path.
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
  A partial incremental visit conservatively unions compatible prior hashes with current hashes.
  Strict variants (Release by default) automatically vary the ASM transform input and verify the
  resulting visits against the scoped class inventory, producing a fresh full snapshot without
  requiring a special command-line flag. `--rerun-tasks` remains a recovery/diagnostic option.
  Advanced gate properties remain available for exceptional compatibility migrations but are not
  required in normal configuration.
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

DexCfgObfuscator is licensed under the [Apache License 2.0](LICENSE).
DexCfgObfuscator 使用 [Apache License 2.0](LICENSE) 开源。

The `stringEncryption` design and migration-compatible API shapes were informed by
[MegatronKing/StringFog](https://github.com/MegatronKing/StringFog); portions of its ASM
visitor/carrier implementation were adapted and substantially modified. DEX processing uses
[google/smali dexlib2](https://github.com/google/smali), and JVM bytecode processing uses
[OW2 ASM](https://asm.ow2.io/). These projects remain under their own licenses and are not endorsed
by this project. Full dependency attribution is in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
