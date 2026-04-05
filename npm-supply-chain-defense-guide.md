# npmサプライチェーン攻撃対策ガイド

**作成日:** 2026年4月5日  
**対象:** npm / Node.jsを利用する開発者・チーム  
**背景:** 2026年3月のaxiosサプライチェーン攻撃（週間1億DL、約3時間でRAT配布）を受けた実務対策

---

## 1. npmサプライチェーン攻撃の3パターン

2025〜2026年に発生したnpmサプライチェーン攻撃は、主に以下の3パターンに分類される。

| パターン | 手法 | 代表事例 |
|----------|------|---------|
| **アカウントハイジャック** | メンテナーのnpm認証情報を窃取し、正規パッケージの悪意あるバージョンを公開 | axios（2026年3月）、ua-parser-js（2021年） |
| **タイポスクワッティング** | 人気パッケージに類似した名前のパッケージを公開 | `axois`、`plain-crypto-js` |
| **依存性混同** | 内部パッケージ名と同名のパッケージを公開レジストリに登録 | Claude Code流出後の`color-diff-napi`等 |

いずれの攻撃でも、npmの`postinstall`ライフサイクルフックが主要な実行ベクトルとなる。`npm install`を実行するだけで、悪意あるコードがユーザーの操作なしに自動実行される。

---

## 2. 今日やるべき対策（優先度順）

### 2.1 最優先：lockfileの厳格運用（npm ci）

**すべてのCI/CDと本番デプロイで`npm install`ではなく`npm ci`を使用する。**

```bash
# ❌ npm install — lockfileを無視して最新版を取得する可能性がある
npm install

# ✅ npm ci — lockfileを厳密に尊重し、整合性チェックも実施
npm ci
```

`npm ci`は以下の点で`npm install`と異なる：

- `package-lock.json`に記録されたバージョンとハッシュを厳密に再現
- `package.json`とlockfileの不一致があればエラーで停止
- `node_modules`を毎回クリーンに再作成

**`package-lock.json`は必ずリポジトリにコミットする。** `.gitignore`に`package-lock.json`を含めている場合は即座に削除する。

### 2.2 postinstallフックの無効化（--ignore-scripts）

```bash
# CI/CDでの推奨設定
npm ci --ignore-scripts

# グローバル設定（開発マシン）
npm config set ignore-scripts true
```

`.npmrc`ファイルでの設定：

```ini
# プロジェクトルートの .npmrc
ignore-scripts=true
```

**注意：** `--ignore-scripts`はネイティブアドオン（`node-gyp`等）のビルドもブロックする。ネイティブアドオンが必要なパッケージは個別に手動実行する：

```bash
npm ci --ignore-scripts
cd node_modules/esbuild && node postinstall.js
```

pnpm v10はpostinstallをデフォルトで無効化しており、必要なパッケージのみ`dependenciesMeta`で個別許可する設計を採用している。npmでも同様の運用が推奨される。

### 2.3 クールダウン（min-release-age）の設定

npm v11.10.0（2026年2月リリース）で`min-release-age`が追加された。公開から指定日数が経過していないパッケージのインストールを拒否する。

```ini
# .npmrc（プロジェクトまたはグローバル）
min-release-age=7
```

```bash
# コマンドラインで指定
npm install --min-release-age=7

# 緊急時にクールダウンをバイパス
npm install <package> --min-release-age=0
```

**axiosの攻撃ウィンドウは約3時間だった。7日間のクールダウンを設定していれば、この攻撃を完全にブロックできた。** 過去8年間の主要サプライチェーン攻撃21件を分析した調査では、7日間のクールダウンで11件の短時間公開型攻撃をブロックできたと推定されている。

#### 各パッケージマネージャーでのクールダウン設定

| ツール | 設定名 | 単位 | 設定例 |
|--------|--------|------|--------|
| **npm** v11.10.0+ | `min-release-age` | 日 | `min-release-age=7` |
| **pnpm** v10.16+ | `minimum-release-age` | 分 | `minimum-release-age=10080`（7日） |
| **Yarn** v4.10.0+ | `npmMinimalAgeGate` | 分 | `npmMinimalAgeGate: 10080` |
| **Bun** v1.3+ | `minimumReleaseAge` | 秒 | `minimumReleaseAge = 604800` |

#### Dependabotとの連携

`min-release-age`を`.npmrc`に設定するだけでは、Dependabotがクールダウン期間内のバージョンに対してPRを作成してしまう。Dependabotのcooldown設定と合わせて使用する：

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    cooldown:
      default-days: 7
      semver-minor-days: 3
      semver-patch-days: 3
```

#### Renovateとの連携

```json
// renovate.json
{
  "minimumReleaseAge": "7 days",
  "packageRules": [
    {
      "matchPackageNames": ["*"],
      "minimumReleaseAge": "7 days"
    }
  ]
}
```

Mend Renovate 42では、npmパッケージに対する3日間のクールダウンがベストプラクティスプリセット（`security:minimumReleaseAgeNpm`）としてデフォルト有効になっている。

### 2.4 バージョンの完全固定

```json
// package.json
{
  "dependencies": {
    "axios": "1.14.0"
  }
}
```

```bash
# ❌ 危険：キャレット（^）やチルダ（~）のバージョンレンジ
"axios": "^1.14.0"   # 1.14.1（悪意あるバージョン）に解決される
"axios": "~1.14.0"   # 同上

# ✅ 安全：完全固定
"axios": "1.14.0"    # 常にこのバージョンのみ
```

`npm install --save-exact`をデフォルトにする：

```ini
# .npmrc
save-exact=true
```

### 2.5 SLSA Provenanceの検証

正規のaxiosリリースはGitHub Actions OIDCフロー経由でSLSA provenance attestation付きで公開されていた。悪意あるバージョンはCLIからの直接公開でprovenanceがなかった。

```bash
# パッケージのprovenanceを確認
npm audit signatures

# SLSA provenanceがないパッケージを警告
npm install --prefer-online
```

npmはクラシック公開トークンを廃止し、OIDC trusted publishingへの移行を推進している。npm v11.10.0では`npm trust`コマンドによる一括OIDC設定が可能になった。

---

## 3. CI/CDパイプライン別の実装例

### 3.1 GitHub Actions

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: '22'
          cache: 'npm'

      - name: Install dependencies (secure)
        run: npm ci --ignore-scripts

      - name: Run necessary postinstall scripts manually
        run: |
          # 必要なパッケージのみ個別にpostinstallを実行
          cd node_modules/esbuild && node postinstall.js || true

      - name: Audit
        run: npm audit --audit-level=high

      - name: Build & Test
        run: |
          npm run build
          npm test
```

### 3.2 GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - install
  - build
  - test

install:
  stage: install
  script:
    - npm ci --ignore-scripts
  cache:
    key: $CI_COMMIT_REF_SLUG
    paths:
      - node_modules/
  rules:
    - changes:
        - package-lock.json

build:
  stage: build
  script:
    - npm run build

test:
  stage: test
  script:
    - npm audit --audit-level=high
    - npm test
```

### 3.3 Dockerfile

```dockerfile
FROM node:22-slim

WORKDIR /app

# lockfileとpackage.jsonのみ先にコピー（レイヤーキャッシュ最適化）
COPY package.json package-lock.json .npmrc ./

# セキュアなインストール
RUN npm ci --ignore-scripts --no-audit

# 必要なpostinstallのみ手動実行
RUN cd node_modules/esbuild && node postinstall.js || true

# ソースコードをコピー
COPY . .

RUN npm run build

# 本番用：devDependenciesを除去
RUN npm prune --production

CMD ["node", "dist/index.js"]
```

プロジェクトルートの`.npmrc`：

```ini
# .npmrc
ignore-scripts=true
save-exact=true
min-release-age=7
engine-strict=true
```

---

## 4. プロキシレジストリの導入

組織レベルでの防御として、npm公開レジストリとの間にプロキシレジストリを配置する。

### 4.1 Verdaccio（軽量・無料）

```yaml
# config.yaml
uplinks:
  npmjs:
    url: https://registry.npmjs.org/
    cache: true
    maxage: 7d  # 7日間キャッシュ

packages:
  '@company/*':
    access: $authenticated
    publish: $authenticated
    # 社内パッケージは公開レジストリに問い合わせない
  '**':
    access: $authenticated
    proxy: npmjs
```

### 4.2 Artifactory / Nexus

- パッケージの公開からの経過日数でフィルタリング
- SLSA provenanceがないパッケージの自動拒否
- 特定パッケージのホワイトリスト管理
- 脆弱性スキャンの統合

---

## 5. 開発マシンの防御

### 5.1 グローバル.npmrc設定

```ini
# ~/.npmrc
ignore-scripts=true
save-exact=true
min-release-age=7
audit=true
fund=false
```

### 5.2 アウトバウンド通信の制限

開発マシンやCI/CDランナーからのアウトバウンド通信をホワイトリスト方式で制限する。これはaxios攻撃のC2通信（`sfrclak[.]com:8000`）をブロックする最も効果的な防御層。

```bash
# 許可すべきドメイン
registry.npmjs.org       # npmレジストリ
github.com               # GitHubソースコード
api.anthropic.com        # Claude API（Claude Code利用時）

# ブロックすべきもの
上記以外のすべてのアウトバウンド通信
```

### 5.3 IDE拡張機能の注意

VSCodeのNX Console等の拡張機能は、プロジェクトを開いただけで自動的にパッケージの依存関係を取得する場合がある。lockfileでバージョンをピン留めしていても、拡張機能が最新版をレジストリから取得してしまうケースが報告されている。

---

## 6. 監視と検知

### 6.1 Socket.dev

リアルタイムでnpmパッケージの異常を検知するサービス。axios攻撃ではSocketが公開から6分以内に`plain-crypto-js@4.2.1`を検出した。

### 6.2 npm audit

```bash
# 定期的な脆弱性スキャン
npm audit

# CI/CDでの自動チェック（高・クリティカルのみで失敗）
npm audit --audit-level=high
```

### 6.3 自前の検知スクリプト

```bash
#!/bin/bash
# postinstallフックを持つパッケージを一覧表示
find node_modules -name "package.json" -maxdepth 2 -exec \
  sh -c 'grep -l "postinstall" "$1" 2>/dev/null && echo "  ⚠️  $1"' _ {} \;
```

---

## 7. axios攻撃でこれらの対策が効いたかの検証

| 対策 | axios攻撃を防げたか | 理由 |
|------|-------------------|------|
| `npm ci`（lockfileピン留め） | **Yes**（条件付き） | lockfileに`axios@1.14.0`が記録されていれば`1.14.1`は取得されない |
| `--ignore-scripts` | **Yes** | postinstallフックが実行されず、RATがダウンロードされない |
| `min-release-age=7` | **Yes** | 公開から3時間のバージョンはクールダウンで拒否される |
| `save-exact=true` | **Yes**（条件付き） | `"axios": "1.14.0"`であれば`1.14.1`に解決されない |
| SLSA Provenance検証 | **Yes** | 悪意あるバージョンにはprovenanceがなかった |
| アウトバウンド制限 | **Yes** | C2（`sfrclak[.]com:8000`）への通信がブロックされる |
| `npm audit` | **No**（事後的） | 攻撃発生時点ではCVEが未登録 |

**最初の3つ（lockfile + ignore-scripts + cooldown）だけで、過去1年間のすべての主要npmサプライチェーン攻撃をブロックできた。**

---

## 8. 推奨する最小構成

以下の設定をすべてのプロジェクトに導入することを推奨する。

**`.npmrc`（プロジェクトルート）：**

```ini
ignore-scripts=true
save-exact=true
min-release-age=7
engine-strict=true
```

**CI/CDコマンド：**

```bash
npm ci --ignore-scripts
```

**`.github/dependabot.yml`：**

```yaml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    cooldown:
      default-days: 7
```

この3ファイルの設定だけで、npmサプライチェーン攻撃のリスクを大幅に低減できる。

---

## 9. 既知の制限と注意事項

| 項目 | 内容 |
|------|------|
| `min-release-age`の除外機能 | npm版は現時点でパッケージ個別の除外機能がない（pnpmの`minimumReleaseAgeExclude`相当）。緊急パッチの即時適用には`--min-release-age=0`で一時的にバイパスが必要 |
| `~`バージョンレンジとの競合 | `min-release-age`と`~`バージョンレンジを併用するとエラーが発生するバグがnpm v11.10.0-11.10.1で報告されている（npm/cli#9005） |
| セキュリティパッチの遅延 | 7日間のクールダウンはゼロデイ修正の適用も7日遅延させる。重要なセキュリティパッチは手動でクールダウンをバイパスして適用する運用が必要 |
| lockfileの信頼性 | lockfileが改ざんされていないことが前提。PRレビューで`package-lock.json`の変更を注意深く確認する |

---

## 10. 参考リンク

### npm公式

- npm `min-release-age`ドキュメント: https://docs.npmjs.com/cli/v11/using-npm/config#min-release-age
- npm `min-release-age` PR: https://github.com/npm/cli/pull/8965

### 解説・ガイド

- Socket.dev「npm Introduces minimumReleaseAge」: https://socket.dev/blog/npm-introduces-minimumreleaseage-and-bulk-oidc-configuration
- ArmorCode「Defending Against NPM Supply Chain Attacks」: https://www.armorcode.com/blog/defending-against-npm-supply-chain-attacks-a-practical-guide
- Andrew Nesbitt「Package Managers Need to Cool Down」: https://nesbitt.io/2026/03/04/package-managers-need-to-cool-down.html
- Dani Akash「Minimum Release Age is an Underrated Supply Chain Defense」: https://daniakash.com/posts/simplest-supply-chain-defense/
- DevelopersIO「npm min-release-age + Dependabot cooldown」: https://dev.classmethod.jp/en/articles/npm-min-release-age-dependabot-cooldown/

### 関連攻撃分析

- Elastic Security Labs（axios詳細分析）: https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all
- SOCRadar（axios IOC・修復ガイド）: https://socradar.io/blog/axios-npm-supply-chain-attack-2026-ciso-guide/
- Snyk（axios対応ガイド）: https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/
- StepSecurity（CI/CD修復手順）: https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan
- DreamFactory（12日間5件の統合分析）: https://blog.dreamfactory.com/five-supply-chain-attacks-in-twelve-days-how-march-2026-broke-open-source-trust-and-what-comes-next
