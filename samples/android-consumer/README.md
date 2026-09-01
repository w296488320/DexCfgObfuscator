# Android consumer sample

This is a neutral Android application. By default it consumes the plugin directly from the current
source checkout through `includeBuild('../..')`; it never reads `mavenLocal()` implicitly. It can
also verify an exact published Maven repository by setting `samplePluginRepository` and
`samplePluginVersion`.

From the repository root, build one of the three protection combinations:

```bash
# String encryption only
./gradlew -p samples/android-consumer :app:assembleRelease \
  -PsampleProtection=string --no-configuration-cache

# DEX control-flow obfuscation only
./gradlew -p samples/android-consumer :app:assembleRelease \
  -PsampleProtection=cfg --no-configuration-cache

# Both protections (also the safe default when the property is omitted)
./gradlew -p samples/android-consumer :app:assembleRelease \
  -PsampleProtection=both --no-configuration-cache

# Both protections after R8 shrinking, optimization, and renaming
./gradlew -p samples/android-consumer :app:assembleRelease \
  -PsampleProtection=both -PsampleMinify=true --no-configuration-cache
```

To verify the public GitHub Pages Maven repository rather than the included source build:

```bash
./gradlew -p samples/android-consumer :app:assembleRelease \
  -PsamplePluginRepository=https://w296488320.github.io/DexCfgObfuscator/maven-repo \
  -PsamplePluginVersion=0.1.2 \
  -PsampleProtection=string \
  --no-configuration-cache
```

The repository and version properties are explicit so CI cannot silently fall back to the source
checkout when online publication is missing or incomplete.

`sampleMinify` accepts only `true` or `false` and defaults to `false`. The minimal consumer rule keeps
`SamplePayload` available for final-DEX inspection while allowing R8 to optimize and rename it, so the
last command also exercises mapping-aware string and CFG verification.

`sampleStringEnablement=selector` exercises the `0.1.2` selector-only path (`enabled=false` with
`enabledVariants=['release']`). Its default value, `global`, exercises the global `enabled=true` path.

The APK is written to `app/build/outputs/apk/release/`. The plugin report is written under
`app/build/reports/dex-cfg-obfuscator/`. `SamplePayload` intentionally contains inspectable string
constants and branch-heavy bytecode; it is test data only and contains no credential or live URL.

## Stack-trace retrace smoke

This source sample exercises the implementation released in `0.1.2`. The published `0.1.0`
artifact does not contain this task. Install Android SDK Command-line Tools before running
the smoke test. CFG preserves valid input source positions and does not rename call frames.

For a non-minified build, run the task against the already readable fixture:

```bash
./gradlew -p samples/android-consumer \
  :app:retraceReleaseDexCfgStackTrace \
  --trace-file="$PWD/samples/android-consumer/fixtures/retrace-release.txt" \
  --output-file="$PWD/samples/android-consumer/app/build/retraced-release.txt" \
  --no-configuration-cache
```

With `-PsampleMinify=false`, the output is an exact copy because the frames are already readable.
The Issue #9 minified path is reproducible with these two commands:

```bash
./gradlew -p samples/android-consumer :app:assembleRelease \
  -PsampleProtection=both \
  -PsampleMinify=true \
  --no-configuration-cache

./gradlew -p samples/android-consumer \
  :app:retraceReleaseDexCfgStackTrace \
  -PsampleProtection=both \
  -PsampleMinify=true \
  --trace-file="$PWD/samples/android-consumer/fixtures/retrace-minified-release.txt" \
  --output-file="$PWD/samples/android-consumer/app/build/retraced-minified-release.txt" \
  --mapping-file="$PWD/samples/android-consumer/app/build/outputs/mapping/release/mapping.txt" \
  --no-configuration-cache
```

The fixed `b.a(SourceFile:1)` fixture belongs only to the checked-in sample and its deterministic R8
mapping; it is not a generic production trace. CI first inspects the final APK and proves that the
strongly flattened `div-int` still has effective residual line `1`, then verifies that official
Retrace restores `ReleaseCrashProbe.divideForRetrace(ReleaseCrashProbe.java:18)`. For an archived
release, always provide that release's private mapping. The task never rebuilds the APK and does not
automatically prove mapping/APK identity, so archive production mappings with version/build identity
and APK/AAB SHA-256. Neither mappings nor crash files are uploaded by the plugin.

`Unknown Source` without a line number or DEX PC cannot be reconstructed after the fact. Retracing a
single stack trace restores call-stack/source context; it cannot recreate every branch taken inside a
method.

## Device crash/retrace check

The launcher remains non-crashing by default. A signed test APK can trigger the CFG-protected crash
path explicitly, so a real `logcat` stack can be checked against the exact Release mapping:

```bash
adb shell am force-stop com.example.dexcfgsample
adb shell am start -W \
  -n com.example.dexcfgsample/.MainActivity \
  --ez com.example.dexcfgsample.CRASH_FOR_RETRACE true
```

Sign the local test APK with a development key before installation; never use that key for a public
release. Extract only the `com.example.dexcfgsample` crash frames from `logcat`, then pass that file
and the same build's `mapping.txt` to `retraceReleaseDexCfgStackTrace`. The expected recovered frames
are `ReleaseCrashProbe.divideForRetrace(...)` and `MainActivity.onCreate(...)` with their original
source lines. The probe is a static pure-integer method whose final division by the supplied zero is
transformed by the strong CFG flattening path; it is never called during a normal launcher start.

This sample performs build-time integration verification. It is not a substitute for installing the
result on supported Android versions and exercising the protected code paths before a production
release.
