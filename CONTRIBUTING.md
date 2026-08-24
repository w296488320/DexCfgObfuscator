# Contributing

Thank you for improving DexCfgObfuscator. Small, focused changes with reproducible tests are easiest to review.

## Development setup

Use JDK 17 and the checked-in Gradle wrapper. Run the same validation used by CI before opening a pull request:

```bash
./gradlew test validatePlugins --no-daemon --no-configuration-cache --no-parallel
git diff --check
```

The normal build may download declared dependencies from the configured repositories. Use Gradle's `--offline` option only after those dependencies are cached.

## Change guidelines

- Add focused tests for transformations, verifier behavior, DSL contracts, and regressions.
- Preserve application/library and incremental-build behavior unless the change explicitly documents a compatibility break.
- Treat public DSL names and generated runtime contracts as compatibility-sensitive APIs.
- Keep logs and fixtures free of application identifiers, credentials, signing material, proprietary APK/DEX files, and customer data.
- Do not commit generated `.gradle/`, `build/`, `maven-repo/`, or `release/` contents.
- Keep unrelated formatting and refactoring out of functional patches.

For a release-bundle preflight, commit the intended source first and run `./build-release.sh`. The script intentionally rejects a dirty worktree and existing artifacts for the same version. `DEXCFG_ALLOW_DIRTY=true` is only for local previews; such output must not be distributed.

## Issues and pull requests

Use the issue templates and include a minimal public reproducer whenever possible. For security-sensitive reports, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

By submitting a contribution, you agree that it is licensed under the repository's `LICENSE` terms and that you have the right to contribute it.
