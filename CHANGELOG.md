# Changelog

All notable user-visible changes are documented in this file. The project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and uses semantic versioning for public releases.

## [Unreleased]

## [0.1.0] - 2026-08-24

### Added

- Pre-D8/R8 `stringEncryption` for Android application and library modules, with package filters,
  BYTES/BASE64 carriers, final-output verification, and pluggable cipher/key-generation APIs.
- StringFog-oriented migration aliases and custom runtime implementation support without a runtime
  dependency on StringFog itself.
- Apache-2.0 project licensing and complete third-party dependency attribution.
- A reproducible Android consumer sample covering string-only, CFG-only, combined, and R8 builds.
- Maven Central POM metadata, signed-bundle generation, and publisher documentation.
- GitHub Pages Maven publication with immutable version merging, public-consumer verification, and
  permanent GitHub Release ZIP/checksum assets.
- Gradle Plugin Portal metadata and publication task wiring.
- Public CI checks for JDK 17, Gradle Wrapper integrity, plugin tests, and plugin validation.
- Security reporting, contribution guidance, issue templates, and automated dependency-update configuration.
- A manual workflow that builds a verified Maven repository bundle without publishing it to an external package repository.

### Changed

- Public coordinates are `io.github.w296488320:dex-cfg-obfuscator:0.1.0` and plugin ID
  `io.github.w296488320.dexcfgobf`; Java implementation packages remain under `com.hunter.*`.
- Release bundles are built from an isolated temporary Maven repository and contain only the current implementation and plugin-marker versions.
- Plugin JARs, documentation JARs, and the outer Maven-repository ZIP are byte-reproducible for an
  exact-tag publication retry.
- Release bundles include the project license, third-party notices, and bilingual documentation while excluding platform metadata such as `.DS_Store`.
- Release builds use network dependency resolution by default; explicit offline operation is available with `DEXCFG_OFFLINE=true`.
