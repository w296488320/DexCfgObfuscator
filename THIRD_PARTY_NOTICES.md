# Third-Party Notices

This file identifies third-party projects intentionally referenced by the design or resolved by
the current Gradle build. It is provided for attribution and dependency transparency. It does not
change the license of DexCfgObfuscator or any third-party work. Copyright and license rights remain
with their respective owners.

`runtime` below means the Gradle plugin's build-process runtime. These libraries are used while an
Android project is being built; they are not injected into the target application's APK by this
plugin. The published plugin is a thin JAR and does not shade or embed the dependency JARs listed
below. Maven/Gradle resolves them as separate artifacts under their own licenses.

## Design reference and migration compatibility

### StringFog

- Project: [MegatronKing/StringFog](https://github.com/MegatronKing/StringFog)
- Copyright: Copyright (C) 2016-2023, Megatron King
- License: [Apache License 2.0](https://github.com/MegatronKing/StringFog/blob/master/LICENSE)
- Scope: the `stringEncryption` feature uses StringFog as an important behavioral and migration
  reference. Portions of the ASM visitor/carrier implementation were adapted from StringFog and
  substantially modified. Referenced concepts also include byte-array ciphertext, package
  selection, pluggable encryption/key generation, and compatibility aliases for existing StringFog
  users. StringFog is not declared as a Maven dependency and its artifact is not included in this
  project.

The adapted source files carry their own upstream copyright and modification notices. StringFog's
name and trademarks remain the property of their respective owners; no endorsement is implied.

## Plugin runtime dependencies

The following versions are the resolved `runtimeClasspath` of the current build.

| Artifact | Version | Relationship | License |
| --- | --- | --- | --- |
| `com.android.tools.smali:smali-dexlib2` | 3.0.9 | direct | BSD-3-Clause, with additional upstream notices reproduced below |
| `org.ow2.asm:asm` | 9.9 | transitive through ASM modules | BSD-3-Clause |
| `org.ow2.asm:asm-tree` | 9.9 | direct | BSD-3-Clause |
| `org.ow2.asm:asm-commons` | 9.9 | direct | BSD-3-Clause |
| `com.google.guava:guava` | 31.1-android | transitive through dexlib2 | Apache-2.0 |
| `com.google.guava:failureaccess` | 1.0.1 | transitive through Guava | Apache-2.0 |
| `com.google.guava:listenablefuture` | 9999.0-empty-to-avoid-conflict-with-guava | transitive empty compatibility artifact | Apache-2.0 |
| `com.google.code.findbugs:jsr305` | 3.0.2 | transitive through dexlib2/Guava | Apache-2.0 |
| `org.checkerframework:checker-qual` | 3.12.0 | transitive through Guava | MIT |
| `com.google.errorprone:error_prone_annotations` | 2.11.0 | transitive through Guava | Apache-2.0 |
| `com.google.j2objc:j2objc-annotations` | 1.3 | transitive through Guava | Apache-2.0 |

Upstream project and license sources:

- [google/smali](https://github.com/google/smali) and its
  [third-party notice](https://github.com/google/smali/blob/main/third_party/NOTICE)
- [OW2 ASM](https://asm.ow2.io/) and its [BSD-3-Clause license](https://asm.ow2.io/license.html)
- [Google Guava](https://github.com/google/guava) (`guava`, `failureaccess`, and
  `listenablefuture`) — Apache-2.0
- [JSR-305 artifact](https://central.sonatype.com/artifact/com.google.code.findbugs/jsr305/3.0.2) —
  Apache-2.0 as declared by its published POM
- [Checker Framework qualifiers](https://github.com/typetools/checker-framework/tree/checker-framework-3.12.0/checker-qual) — MIT
- [Error Prone annotations](https://github.com/google/error-prone/tree/v2.11.0/annotations) — Apache-2.0
- [J2ObjC annotations](https://github.com/google/j2objc/tree/1.3/annotations) — Apache-2.0

The complete Apache-2.0 text is present in this repository's `LICENSE` file. That license text is
also the applicable license text for the Apache-2.0 components listed above; the repository license
does not transfer ownership of those components.

### smali / dexlib2 notices

The upstream `smali-dexlib2:3.0.9` artifact includes the following notices.

Copyright (c) 2010 Ben Gruver (JesusFreke)
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted
provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions
   and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of
   conditions and the following disclaimer in the documentation and/or other materials provided
   with the distribution.
3. The name of the author may not be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.

Unless otherwise stated in the upstream code or commit message, changes by the identified Google
committers are covered by the following notice:

Copyright 2011, Google LLC

Redistribution and use in source and binary forms, with or without modification, are permitted
provided that the following conditions are met:

- Redistributions of source code must retain the above copyright notice, this list of conditions
  and the following disclaimer.
- Redistributions in binary form must reproduce the above copyright notice, this list of
  conditions and the following disclaimer in the documentation and/or other materials provided
  with the distribution.
- Neither the name of Google LLC nor the names of its contributors may be used to endorse or promote
  products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The upstream smali distribution also identifies portions from the Android Open Source Project and
Guava under Apache-2.0:

- Copyright (C) 2007 The Android Open Source Project
- Portions from [Google Guava](https://github.com/google/guava)

The full upstream notice is available at
[google/smali `third_party/NOTICE`](https://github.com/google/smali/blob/main/third_party/NOTICE).

### ASM notice

ASM: a very small and fast Java bytecode manipulation framework

Copyright (c) 2000-2011 INRIA, France Telecom
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted
provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions
   and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of
   conditions and the following disclaimer in the documentation and/or other materials provided
   with the distribution.
3. Neither the name of the copyright holders nor the names of its contributors may be used to
   endorse or promote products derived from this software without specific prior written
   permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

### Checker Framework qualifiers notice

Checker Framework qualifiers

Copyright 2004-present by the Checker Framework developers

MIT License:

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Build and test dependencies

These dependencies are used to compile or test the plugin. They are not published as plugin runtime
dependencies and are not bundled in the plugin JAR or a consumer APK.

| Artifact/tool | Version | Scope | License |
| --- | --- | --- | --- |
| Android Gradle Plugin (`com.android.tools.build:gradle`) | 9.3.1 | `compileOnly` | Apache-2.0 |
| Android Gradle Plugin API (`com.android.tools.build:gradle-api`) | 9.3.1 | `testRuntimeOnly` | Apache-2.0 |
| Android Builder (`com.android.tools.build:builder`) | 9.3.1 | `testRuntimeOnly` | Apache-2.0 |
| JUnit 4 (`junit:junit`) | 4.13.2 | `testImplementation` | EPL-1.0 |
| Hamcrest Core (`org.hamcrest:hamcrest-core`) | 1.3 | transitive test dependency of JUnit | BSD-3-Clause |
| Gradle Wrapper / Gradle distribution | 9.6.1 | build tool | Apache-2.0 |

Their upstream license sources are:

- [Android Gradle Plugin / Android tools/base](https://android.googlesource.com/platform/tools/base/) — Apache-2.0
- [JUnit 4.13.2](https://github.com/junit-team/junit4/tree/r4.13.2) and its
  [EPL-1.0 license](https://github.com/junit-team/junit4/blob/r4.13.2/LICENSE-junit.txt)
- [Hamcrest 1.3](https://github.com/hamcrest/JavaHamcrest/tree/hamcrest-java-1.3) and its
  [BSD license](https://github.com/hamcrest/JavaHamcrest/blob/hamcrest-java-1.3/LICENSE.txt)
- [Gradle](https://github.com/gradle/gradle) — Apache-2.0

Android Gradle Plugin's test-only transitive dependency graph is intentionally not duplicated here:
those artifacts are neither part of the published plugin dependency graph nor redistributed in the
release. They remain governed by the license metadata and notices shipped with their own artifacts.
