# Security Policy

## Supported versions

Security fixes are provided for the latest tagged release. Pre-release snapshots and older releases may be used to reproduce a report, but are not maintained as separate security branches.

## Reporting a vulnerability

Please use GitHub's private **Report a vulnerability** form in the repository's Security tab. Do not open a public issue for a suspected vulnerability.

Include only the information needed to reproduce and assess the problem:

- affected plugin, Gradle, AGP, and JDK versions;
- whether the affected module is an Android application or library;
- a minimal reproducer or sanitized transformation details;
- expected impact and any known workaround.

Do not submit credentials, signing keys, proprietary APK/DEX files, customer data, or unrelated application source. If private vulnerability reporting is unavailable, open a public issue containing no vulnerability details and ask the maintainer to establish a private contact channel.

The maintainer will acknowledge the report, assess affected versions, and coordinate disclosure after a fix or mitigation is available. No response or fix deadline is guaranteed.

## Scope

Examples of in-scope reports include unsafe transformation output, verification bypasses that contradict documented guarantees, arbitrary file access during a normal build, and dependency or release-artifact integrity problems. General reverse-engineering limitations already documented by the project are not vulnerabilities by themselves.
