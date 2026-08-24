# Android consumer sample

This is a neutral Android application that consumes the plugin directly from the current source
checkout through `includeBuild('../..')`. It does not read `mavenLocal()` or `maven-repo/`.

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

`sampleMinify` accepts only `true` or `false` and defaults to `false`. The minimal consumer rule keeps
`SamplePayload` available for final-DEX inspection while allowing R8 to optimize and rename it, so the
last command also exercises mapping-aware string and CFG verification.

The APK is written to `app/build/outputs/apk/release/`. The plugin report is written under
`app/build/reports/dex-cfg-obfuscator/`. `SamplePayload` intentionally contains inspectable string
constants and branch-heavy bytecode; it is test data only and contains no credential or live URL.

This sample performs build-time integration verification. It is not a substitute for installing the
result on supported Android versions and exercising the protected code paths before a production
release.
