# dex-cfg-obfuscator

Android DEX **控制流混淆** Gradle 插件（基本块重排）。**私有、纯本地、不走任何云端。**

在 R8 产出最终 DEX **之后**、打包**之前**，对指定包名下的方法做基本块物理重排：
执行序完全靠 goto/条件跳转串联，语义与原方法逐指令一致，但物理布局被彻底打散。
底层直接操作 smali-dexlib2 指令，用具名 Label 让 dexlib2 自动重算分支偏移、
自动把 `GOTO`→`GOTO_16`→`GOTO_32` 升格，规避 dex2jar IR 往返导致的
`Unsigned short value out of range: 65540` 崩溃；零新增寄存器；已用真机 ART `dex2oat` 校验语义等价。

## 这是什么分发方式（重要）

- 插件产物是 **JAR**（Gradle 插件不可能是 AAR，AAR 是 Android 库格式）。
- 打包好的产物提交在本仓库的 **`maven-repo/`** 文件夹里 —— **它本身就是一个文件夹式 Maven 私有仓库**。
- 别的项目只要把本仓库 `git clone` / `git pull` 到本地，用一行本地路径指向 `maven-repo/` 即可，
  **无需联网、无需重新构建、无需 mavenLocal**。

## 别的项目怎么用（3 步）

### 1. clone 本仓库到本地（建议与你的工程同级目录）

```bash
# 例：与 YourApp 同级
git clone git@github.com:<你的私有仓库>/DexCfgObfuscator.git
# 目录结构：
#   Developer/YourApp
#   Developer/DexCfgObfuscator/maven-repo   <- 私有仓库
```

### 2. 在 `settings.gradle` 的 pluginManagement 里加本地仓库

```groovy
pluginManagement {
    // 默认假设 DexCfgObfuscator 与本工程同级；否则用 gradle.properties 的
    // dexCfgObfuscatorRepo=/自定义路径 覆盖。
    def dexObfRepo = providers.gradleProperty("dexCfgObfuscatorRepo")
            .getOrElse("../DexCfgObfuscator/maven-repo")
    repositories {
        maven {
            name "DexCfgObfuscatorLocalRepo"
            url = uri(file(dexObfRepo).isAbsolute()
                    ? file(dexObfRepo)
                    : new File(rootDir, dexObfRepo))
        }
        gradlePluginPortal(); google(); mavenCentral()
    }
}
```

### 3. 在 Android application 模块 `app/build.gradle` 应用并配置

```groovy
plugins {
    id 'com.android.application'
    id 'com.zhenxi.dexcfgobf' version '1.0.0'
}

dexControlFlowObfuscator {
    enabled true                       // 总开关
    onlyReleaseByDefault true          // true=仅 release；false=debug 也混淆（方便本地测试）
    obfClass = ["com.your.pkg"]        // 需要混淆的包/类前缀
    blackClass = []                    // 例外：命中则不混淆
}
```

- release：开了 `minifyEnabled true`（有 `minify<Variant>WithR8`）即生效，混淆 R8 产物。
- debug：无 R8 时自动锚定 `mergeProjectDex<Variant>`，只混淆项目类，不碰第三方库。

## 配置项

| 字段 | 默认 | 说明 |
|------|------|------|
| `enabled` | `true` | 总开关 |
| `onlyReleaseByDefault` | `true` | 仅 release 生效；设 false 则 debug 也混淆 |
| `depth` | `2` | 混淆强度（预留） |
| `obfClass` | `[]` | 要混淆的包/类前缀；空表示用内置默认 |
| `blackClass` | `[]` | 例外前缀（追加到内置排除表） |
| `skipMethodsWithTryCatch` | `true` | 跳过含 try/catch 的方法（稳定优先） |
| `maxInstructions` | `1500` | 方法指令数上限，超过则跳过 |

## 改了算法后如何更新私有仓库

```bash
cd DexCfgObfuscator
# 改完 src/ 后重新发布到 maven-repo/
./gradlew publish
# 提交（maven-repo/ 会随之更新；改版本号就把 build.gradle 的 version 和使用方的 version 一起改）
git add -A && git commit -m "update obfuscator" && git push
```

## 本地开发/测试

```bash
./gradlew test     # JVM 单测（含语义等价模拟）
./gradlew publish  # 发布到本仓库 maven-repo/
```
