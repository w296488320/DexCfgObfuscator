## Summary

Describe the user-visible behavior and why the change is needed.

## Validation

- [ ] `./gradlew test validatePlugins --no-daemon --no-configuration-cache --no-parallel`
- [ ] `git diff --check`
- [ ] New or changed behavior has focused tests.
- [ ] No generated `build/`, `maven-repo/`, or `release/` artifacts are included.
- [ ] No credentials, signing files, proprietary APK/DEX files, or private application data are included.

## Compatibility

Describe any impact on Gradle/AGP support, application versus library modules, R8, incremental builds, or the public DSL.
