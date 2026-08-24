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
  -PsamplePluginVersion=0.1.0 \
  -PsampleProtection=string \
  --no-configuration-cache
```

The repository and version properties are explicit so CI cannot silently fall back to the source
checkout when online publication is missing or incomplete.

`sampleMinify` accepts only `true` or `false` and defaults to `false`. The minimal consumer rule keeps
`SamplePayload` available for final-DEX inspection while allowing R8 to optimize and rename it, so the
last command also exercises mapping-aware string and CFG verification.

The APK is written to `app/build/outputs/apk/release/`. The plugin report is written under
`app/build/reports/dex-cfg-obfuscator/`. `SamplePayload` intentionally contains inspectable string
constants and branch-heavy bytecode; it is test data only and contains no credential or live URL.

This sample performs build-time integration verification. It is not a substitute for installing the
result on supported Android versions and exercising the protected code paths before a production
release.
