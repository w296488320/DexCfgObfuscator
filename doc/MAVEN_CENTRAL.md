# 在线发布：GitHub Pages、Gradle Plugin Portal 与 Maven Central

本文档只描述发布者流程。普通使用者不需要 GitHub、Gradle 或 Sonatype 发布账号，也不需要 Token
或 GPG 私钥。

## 0. 渠道选择

- **GitHub Pages Maven**：当前首选公开入口。仓库确认可公开并完成一次性 Pages 设置后，推送精确
  匹配项目版本的 `v<version>` tag，自动发布完整 Maven 仓库，并创建同版本 GitHub Release 离线
  附件。使用者匿名读取。
- **Gradle Plugin Portal**：最符合 Gradle plugins DSL 使用习惯，但需要单独注册 Gradle 账号和 API key，
  首版可能进入人工审核。
- **Maven Central**：标准 Maven 镜像，需 namespace、PGP 与独立的 Portal 发布流程。

三个渠道共享 canonical plugin ID `io.github.w296488320.dexcfgobf`，但发布状态互相独立。GitHub
Pages 上线不应伪装成 Portal/Central 已通过审核。

项目的公开坐标是：

```text
implementation: io.github.w296488320:dex-cfg-obfuscator:<version>
plugin marker:  io.github.w296488320.dexcfgobf:
                io.github.w296488320.dexcfgobf.gradle.plugin:<version>
plugin id:      io.github.w296488320.dexcfgobf
```

Java/Groovy 包名继续使用 `com.hunter.*`。Maven 坐标和 JVM 包名是两套独立标识，不需要为发布而搬迁源码。

## 1. 注册 Central Portal 并验证 namespace

1. 打开 <https://central.sonatype.com/>，建议直接使用 GitHub 账号 `w296488320` 登录。
2. 接受发布者条款。
3. 在 **Namespaces** 中确认 `io.github.w296488320` 已处于 `Verified` 状态。

Sonatype 通常会为 GitHub 登录用户自动验证 `io.github.<GitHub 用户名>`。如果没有自动创建，按照页面提供的
verification key 建立临时公开仓库完成验证，或联系 Central Support。不要尝试发布旧的 `com.hunter` marker；
除非确实拥有并验证了 `hunter.com`，否则该 namespace 不属于本账号。

官方说明：

- <https://central.sonatype.org/register/central-portal/>
- <https://central.sonatype.org/register/namespace/>

## 2. 创建并公开 GPG 签名密钥

Maven Central 要求实现 JAR、sources JAR、javadoc JAR 和 POM 都带有 PGP detached signature。

先确认本机已安装 GnuPG；当前 macOS 环境若提示 `gpg: command not found`，可在已安装 Homebrew 的前提下执行：

```bash
brew install gnupg
gpg --version
```

```bash
gpg --full-generate-key
gpg --list-secret-keys --keyid-format LONG
gpg --keyserver keyserver.ubuntu.com --send-keys <完整主密钥指纹>
```

请使用有密码保护的主密钥进行签名，并把公钥发送到 Central 支持的 keyserver。私钥、密码、Portal Token、
`.asc` 以外的密钥材料都不得提交到 Git。

官方说明：<https://central.sonatype.org/publish/requirements/gpg/>

## 3. 生成待手工上传的 Central bundle

推荐首次发布采用此流程。它不需要 Portal Token，也不会自动上传或发布。

正式 bundle 默认只允许从干净工作树生成，并要求当前 `HEAD` 带有与版本完全对应的
`v<version>` tag。先完成代码审查、测试和提交，再创建 tag，例如当前版本：

```bash
git status --short
git tag -a v0.1.0 -m 'DexCfgObfuscator 0.1.0'
```

```bash
export MAVEN_GPG_PRIVATE_KEY="$(gpg --armor --export-secret-keys <完整主密钥指纹>)"
read -s MAVEN_GPG_PASSWORD
export MAVEN_GPG_PASSWORD
./build-central-bundle.sh
unset MAVEN_GPG_PRIVATE_KEY MAVEN_GPG_PASSWORD
```

脚本会：

1. 运行测试和 Gradle 插件校验；
2. 生成 implementation publication 与 plugin marker publication；
3. 生成 sources、javadoc、POM、Gradle metadata、MD5/SHA-1/SHA-256/SHA-512 和 `.asc`；
4. 校验 POM 必需字段、JAR 中的许可证、MD5/SHA-1 内容，并确认 detached PGP signature 文件齐全；
5. 只把当前版本打成 Maven-layout ZIP，并额外生成 ZIP 的 SHA-256。

脚本不在本机导入私钥来二次验证 `.asc`；Central Portal 会执行最终的 PGP 验证。需要在尚未提交或
尚未打 tag 时验证 bundle 结构，可显式运行下列本地预演；预演产物不得上传：

```bash
DEXCFG_CENTRAL_PREVIEW=true ./build-central-bundle.sh
```

默认输出：

```text
release/dex-cfg-obfuscator-<version>-central-bundle.zip
release/dex-cfg-obfuscator-<version>-central-bundle.zip.sha256
```

如果 CI 不方便保存多行环境变量，可使用 Base64：

```bash
export MAVEN_GPG_PRIVATE_KEY_BASE64="$(gpg --armor --export-secret-keys <完整主密钥指纹> | base64 | tr -d '\n')"
read -s MAVEN_GPG_PASSWORD
export MAVEN_GPG_PASSWORD
./build-central-bundle.sh
unset MAVEN_GPG_PRIVATE_KEY_BASE64 MAVEN_GPG_PASSWORD
```

也可将以下内容放入用户级 `~/.gradle/gradle.properties`，并执行 `chmod 600`；不要放入项目目录：

```properties
signingKeyBase64=<ASCII-armored 私钥的单行 Base64>
signingPassword=<私钥密码>
```

## 4. 在 Portal 手工检查并发布

1. 登录 <https://central.sonatype.com/publishing>。
2. 选择 **Publish Component**，上传 `*-central-bundle.zip`。
3. 等待校验；逐项确认 implementation 和 plugin marker 坐标、POM、sources、javadoc、签名均通过。
4. 首次发布建议保持 `USER_MANAGED`，确认无误后才点击 **Publish**。

上传 bundle 的官方说明：<https://central.sonatype.org/publish/publish-portal-upload/>

Central 发布物不可覆盖、删除或用同一版本重新上传。任何修改都必须提升版本，所以只能从干净提交和对应 tag
生成正式 bundle。官方说明：<https://central.sonatype.org/publish/requirements/immutability/>

## 5. 可选：使用 Token 从 Gradle 传到 Portal staging

熟悉手工流程后，可在 Portal 的 <https://central.sonatype.com/usertoken> 生成 Portal User Token。页面只显示
一次 token username/password，请存入密码管理器；它不是 Central 登录密码。

```bash
export MAVEN_CENTRAL_USERNAME='<token username>'
read -s MAVEN_CENTRAL_PASSWORD
export MAVEN_CENTRAL_PASSWORD
export MAVEN_GPG_PRIVATE_KEY="$(gpg --armor --export-secret-keys <完整主密钥指纹>)"
read -s MAVEN_GPG_PASSWORD
export MAVEN_GPG_PASSWORD

MAVEN_CENTRAL_PUBLISHING=true ./gradlew stageCentralPortalDeployment \
    --no-daemon --no-configuration-cache

unset MAVEN_CENTRAL_USERNAME MAVEN_CENTRAL_PASSWORD \
    MAVEN_GPG_PRIVATE_KEY MAVEN_GPG_PASSWORD
```

该任务使用 Sonatype OSSRH Staging API compatibility service 上传两个 publication，再转交 Portal，发布类型固定为
`USER_MANAGED`。它只把内容放入 Portal 等待人工检查，绝不会执行最终的不可逆 Publish。任务会在任何网络上传前
再次要求干净工作树和 `v<version>` tag。

不要让同一个 Central 账号在同一出口 IP 上并发执行此兼容 staging 流程；Maven-like PUT 和 hand-off 必须由
同一出口 IP 完成。CI 应按 namespace 设置 concurrency。若 hand-off 超时或返回状态不明确，先检查 Portal，
不要直接重试，以免生成重复 deployment。

若上传中断并留下 staging repository，按 Sonatype 官方恢复流程先调用
`GET /manual/search/repositories?ip=any&profile_id=<namespace>` 查明 repository key；确认它不是有效 deployment
后，再调用 `DELETE /manual/drop/repository/<repository-key>`。删除 staging repository 与 Central 最终 Publish
不是一回事，但操作前仍应核对 namespace、版本和 key。

也可把 `mavenCentralUsername`、`mavenCentralPassword`、`signingKeyBase64`、`signingPassword` 放进权限为
`0600` 的用户级 `~/.gradle/gradle.properties`。不得写入仓库、命令行参数、CI 日志或 Release 附件。

官方说明：

- <https://central.sonatype.org/publish/generate-portal-token/>
- <https://central.sonatype.org/publish/publish-portal-ossrh-staging-api/>

## GitHub Pages、Maven Central 与 Gradle Plugin Portal 的区别

- **GitHub Pages Maven** 托管本项目生成的完整静态 Maven layout。workflow 只接受指向 `main` 历史、
  且名称精确等于 `v<project.version>` 的 tag；同版本只能字节完全一致地重试，不能覆盖。正式 tag 前
  需先确认历史中没有凭据/私有数据、把仓库设为 **Public**，再在 Settings → Pages 将 Source 设为
  **GitHub Actions**。普通 `GITHUB_TOKEN` 不能代替维护者执行这两个一次性权限操作。

- **Maven Central** 托管普通 Maven publication。本项目同时上传实现组件和 Gradle plugin marker 后，宿主可在
  `pluginManagement.repositories` 中添加 `mavenCentral()`，再通过 plugins DSL 使用插件。
- **Gradle Plugin Portal** 是单独的插件目录和审核/发布系统。发布到 Maven Central 不会自动出现在 Plugin
  Portal；如需 `gradlePluginPortal()` 单独解析，还需要 Gradle 账号、Portal API key 和
  `com.gradle.plugin-publish` 发布流程。
- 三边可以使用同一个 canonical plugin ID `io.github.w296488320.dexcfgobf`，但版本发布是三个独立动作。

Plugin Portal 本地任务图和 metadata 可先检查：

```bash
./gradlew clean test validatePlugins
./gradlew publishPlugins --validate-only --dry-run
```

真实 Portal 校验/上传需要把 `GRADLE_PUBLISH_KEY`、`GRADLE_PUBLISH_SECRET` 放在私有环境变量或
用户级 `~/.gradle/gradle.properties`，再执行：

```bash
./gradlew publishPlugins --validate-only
./gradlew publishPlugins
```

不得把这两个值写入仓库、命令行参数、构建日志或 Release 附件。`--validate-only` 仍会连接 Portal，
因此没有 API 凭据时只能做前述 `--dry-run` 和本地 `validatePlugins`。

实际顺序建议先发布并验证 GitHub Pages，让使用者立即可接入；再分别完成 Plugin Portal 与 Maven
Central 的账号审核。任何渠道已发布的版本都不应覆盖，修改后必须提升版本并创建新 tag。
