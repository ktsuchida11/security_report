# Maven (mvn) における依存関係クールダウン設定 調査レポート

**作成日**: 2026年4月10日  
**対象**: Java / Maven エコシステムのサプライチェーン攻撃対策としてのクールダウン設定

---

## 結論（サマリー）

**Maven 本体にはクールダウン機能が存在しない。** npm の `min-release-age` や uv の `exclude-newer` に相当するネイティブ機能は、Maven / Gradle ともに未実装であり、提案（proposal）すら確認されていない。

Java エコシステムでクールダウンを実現するには、**依存関係更新ツール側**（Dependabot / Renovate）で制御する必要がある。

---

## 1. Maven 本体の現状

Andrew Nesbitt の包括的な調査記事「Package Managers Need to Cool Down」（2026年3月）によると、Maven・Gradle・Swift Package Manager・Dart (pub)・Elixir (Hex) については、クールダウンに関する議論自体が確認されていない。

同様に Dani Akash の調査（2026年3月）でも「Go, Maven, Gradle, Composer, Bundler? Nothing. No support. No proposals for some of them.」と明記されている。

つまり、`pom.xml` や `settings.xml` レベルでの `exclude-newer` 相当の設定は不可能である。

---

## 2. 対策① — GitHub Dependabot のクールダウン設定

Dependabot は 2025年7月に cooldown 機能を GA リリースした。Maven エコシステムもサポート対象に含まれる。

### 設定ファイル: `.github/dependabot.yml`

```yaml
version: 2
updates:
  - package-ecosystem: "maven"
    directory: "/"
    schedule:
      interval: "weekly"
    cooldown:
      default-days: 7
      semver-major-days: 14
      semver-minor-days: 7
      semver-patch-days: 3
```

### 主な仕様

| 項目 | 内容 |
|---|---|
| 対象 | バージョン更新のみ（セキュリティ更新はバイパス） |
| 単位 | 日数（相対値） |
| SemVer レベル制御 | major / minor / patch 個別に設定可能 |
| include / exclude | 特定パッケージをクールダウン対象に含める／除外できる |

### 公式ドキュメント

- https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference

---

## 3. 対策② — Renovate の minimumReleaseAge

Renovate は `minimumReleaseAge`（旧名: `stabilityDays`）を長年サポートしており、Maven Central の `releaseTimestamp` を利用して動作する。

### 設定ファイル: `renovate.json`

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:recommended"],
  "minimumReleaseAge": "7 days",
  "packageRules": [
    {
      "matchDatasources": ["maven"],
      "minimumReleaseAge": "14 days"
    }
  ]
}
```

### ベストプラクティス設定を使う場合

```json
{
  "extends": ["config:best-practices"],
  "minimumReleaseAge": "14 days"
}
```

### 主な仕様

| 項目 | 内容 |
|---|---|
| 動作 | 設定期間未満のリリースに "pending" ステータスを付与 |
| セキュリティ更新 | バイパス（即時反映） |
| タイムスタンプ不在時 | Renovate 42 以降、未到達扱い（安全側に倒す） |
| 推奨値 | automerge 使用時は 14 days |

### 公式ドキュメント

- https://docs.renovatebot.com/key-concepts/minimum-release-age/
- https://docs.renovatebot.com/upgrade-best-practices/

---

## 4. 対策③ — OpenRewrite による自動設定

既存の Maven プロジェクトに対して、OpenRewrite レシピで Dependabot cooldown 設定を一括追加できる。

```xml
<plugin>
  <groupId>org.openrewrite.maven</groupId>
  <artifactId>rewrite-maven-plugin</artifactId>
  <version>6.36.0</version>
  <configuration>
    <activeRecipes>
      <recipe>org.openrewrite.github.AddDependabotCooldown</recipe>
    </activeRecipes>
  </configuration>
  <dependencies>
    <dependency>
      <groupId>org.openrewrite.recipe</groupId>
      <artifactId>rewrite-github-actions</artifactId>
      <version>3.20.0</version>
    </dependency>
  </dependencies>
</plugin>
```

実行: `mvn rewrite:run`

### 公式ドキュメント

- https://docs.openrewrite.org/recipes/github/adddependabotcooldown

---

## 5. 推奨構成（Maven プロジェクト向け）

Maven 本体にネイティブ機能がない以上、**多層防御**で対処する：

```
┌─────────────────────────────────────────────┐
│  Layer 1: Dependabot cooldown               │
│  → dependabot.yml で 7日クールダウン         │
├─────────────────────────────────────────────┤
│  Layer 2: Renovate minimumReleaseAge        │
│  → renovate.json で 14日（automerge時）      │
├─────────────────────────────────────────────┤
│  Layer 3: バージョンピンニング               │
│  → pom.xml で直接・推移依存のバージョン固定  │
│  → Maven Enforcer Plugin で制約を強制        │
├─────────────────────────────────────────────┤
│  Layer 4: 脆弱性スキャン                     │
│  → Snyk / Trivy / Dependabot alerts          │
│  → セキュリティ更新はクールダウンをバイパス   │
└─────────────────────────────────────────────┘
```

---

## 6. 他エコシステムとの比較

| パッケージマネージャ | ネイティブクールダウン | 相対値 | 設定名 |
|---|---|---|---|
| uv (Python) | ✅ v0.9.17〜 | ✅ | `exclude-newer` |
| npm | ✅ v11.10.0〜 | ✅ | `min-release-age` |
| pnpm | ✅ v10.16〜 | ✅ | `minimumReleaseAge` |
| Yarn | ✅ v4.10.0〜 | ✅ | `npmMinimalAgeGate` |
| pip | ✅ v26.0〜 | ❌（絶対値のみ） | `--uploaded-prior-to` |
| Cargo (Rust) | 🔧 RFC進行中 | — | — |
| **Maven** | **❌ なし** | — | — |
| **Gradle** | **❌ なし** | — | — |

---

## 参考資料

1. Andrew Nesbitt, "Package Managers Need to Cool Down" (2026-03-04)  
   https://nesbitt.io/2026/03/04/package-managers-need-to-cool-down.html

2. GitHub Docs — Dependabot options reference  
   https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference

3. Renovate Docs — Minimum Release Age  
   https://docs.renovatebot.com/key-concepts/minimum-release-age/

4. OpenRewrite — AddDependabotCooldown  
   https://docs.openrewrite.org/recipes/github/adddependabotcooldown

5. Dani Akash, "Minimum Release Age is an Underrated Supply Chain Defense" (2026-03)  
   https://daniakash.com/posts/simplest-supply-chain-defense/

6. William Woodruff, "We should all be using dependency cooldowns" (2025-11-21)  
   https://blog.yossarian.net/2025/11/21/We-should-all-be-using-dependency-cooldowns
