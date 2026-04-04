# axiosサプライチェーン攻撃 詳細調査レポート

**作成日:** 2026年4月2日  
**対象:** npm版Claude Code利用者・Node.js開発者  
**脅威レベル:** Critical（GHSA-fw8c-xr5c-95f9）  
**帰属:** UNC1069（北朝鮮関連脅威アクター、Mandiant/Google TIG分析）

---

## 1. 攻撃の概要

2026年3月31日、npmパッケージ「axios」（週間約1億ダウンロード）のメインメンテナー`jasonsaayman`のアカウントが侵害され、**バックドア入りの2バージョンが公式レジストリに公開された**。悪意あるバージョンは`postinstall`フックを通じて、macOS・Windows・Linuxのすべてのプラットフォームに**クロスプラットフォームRAT（Remote Access Trojan）**を自動デプロイする。

axiosはJavaScriptエコシステムで最も広く使われるHTTPクライアントライブラリであり、**クラウド/コード環境の約80%に存在する**（Wiz調査）。Claude Codeもaxiosを依存関係として使用しているため、npm版Claude Codeユーザーも影響範囲内にある。

---

## 2. 日本時間（JST）でのタイムライン — いつがアウトか

以下はすべてUTCから**+9時間**でJSTに変換した正確なタイムラインである。

| JST時刻 | UTC時刻 | イベント |
|---------|---------|---------|
| 3/30 14:57 | 3/30 05:57 | `plain-crypto-js@4.2.0`公開（無害なデコイ。レジストリ上の信頼構築用） |
| 3/31 08:59 | 3/30 23:59 | `plain-crypto-js@4.2.1`公開（マルウェア本体を含むバージョン） |
| **3/31 09:21** | **3/31 00:21** | **`axios@1.14.1`公開（`latest`タグ） — 感染ウィンドウ開始** |
| **3/31 10:00** | **3/31 01:00** | **`axios@0.30.4`公開（`legacy`タグ） — レガシーユーザーも影響下に** |
| 3/31 10:50 | 3/31 01:50 | Elastic Security LabsがGitHubセキュリティアドバイザリを提出 |
| **3/31 12:15〜12:30頃** | **3/31 03:15〜03:30頃** | **npmが悪意あるバージョンを削除 — 感染ウィンドウ終了** |

### 判定基準：アウト or セーフ

| 条件 | 判定 |
|------|------|
| `package-lock.json`で`axios@1.14.0`以前にピン留めしており、`npm ci`を使用していた | **セーフ** |
| 感染ウィンドウ外（JST 3/31 09:21より前、または12:30以降）に`npm install`した | **セーフ** |
| `--ignore-scripts`オプションをつけて`npm install`していた | **セーフ**（postinstallが実行されない） |
| **JST 3/31 09:21〜12:30の間に`npm install`または`npm update`を実行した** | **アウト（要調査）** |
| 上記時間帯にCI/CDパイプラインが`npm install`を実行した | **アウト（要調査）** |
| 上記時間帯にDockerイメージをビルドし、その中で`npm install`を実行した | **アウト（そのイメージとビルドランナーを調査）** |
| `axios@1.14.0`より古いバージョンを使い続けていた | **セーフ** |

**重要:** `latest`タグが汚染されたため、`npm install axios`（バージョン指定なし）は自動的に悪意あるv1.14.1を取得した。`package-lock.json`をコミットし`npm ci`を使っていれば影響を受けない。

---

## 3. 攻撃の技術的詳細 — 何が起きるか

### 感染フロー

```
npm install axios@1.14.1
  └→ 依存関係として plain-crypto-js@4.2.1 を取得
       └→ postinstall フック: node setup.js が自動実行
            ├→ OS検出 (os.platform())
            ├→ C2サーバー sfrclak[.]com:8000 にHTTP POST
            │   └→ User-Agent偽装: packages.npm.org/product{0,1,2}
            ├→ プラットフォーム別ペイロードをダウンロード・実行
            └→ 自己消去（setup.js削除 + package.json差し替え）
```

### プラットフォーム別ペイロード

| OS | Stage-2ファイル | 偽装名 | 実装言語 | 永続化 |
|----|----------------|--------|----------|--------|
| macOS | `/Library/Caches/com.apple.act.mond` | Apple系デーモン | C++ (Mach-O) | なし |
| Windows | `%PROGRAMDATA%\wt.exe` + `%TEMP%\6202033.ps1` | Windows Terminal | PowerShell | レジストリRunキー + 隠しbatファイル |
| Linux | `/tmp/ld.py` | 汎用ローダー | Python | なし |

### RATの機能

3プラットフォームすべてで**同一のC2プロトコル**を使用する統一RATフレームワーク：

- **ビーコン間隔:** 60秒ごとにC2にチェックイン
- **初回偵察:** ホスト名、ユーザー名、OS、タイムゾーン、ブートタイム、ハードウェアモデル、CPU、全プロセスリスト
- **コマンド実行:** 任意のシェルコマンド/スクリプト実行
- **バイナリ注入:** 追加マルウェアのドロップ＆実行
- **ディレクトリ列挙:** ファイルシステムのブラウジング
- **認証情報の窃取:** AWS鍵、APIトークン、SSH鍵、`.env`ファイル、各種クレデンシャル

### アンチフォレンジック

マルウェアは実行後、**自身の痕跡を徹底的に消去する**：

1. `setup.js`をファイルシステムから削除
2. `package.json`を無害なv4.2.0のコピーで上書き
3. `node_modules/plain-crypto-js/`内には**postinstallフックの痕跡が残らない**

これにより、事後の`node_modules`検査では感染を検出できない。`package-lock.json`とnpm audit logのみが証拠を保持する。

---

## 4. コンテナ環境（Docker / CI/CD）での影響分析

### 4.1 エフェメラル（一時的）コンテナの場合

**Dockerマルチステージビルドで`npm install`したケース：**

| シナリオ | 影響 | 理由 |
|----------|------|------|
| ビルドステージのみで`npm install`、ランタイムイメージにはビルド成果物のみコピー | **ビルドイメージ内では実行されたが、ランタイムイメージには残らない可能性がある** | ただしpostinstallはビルド時に実行されるため、ビルド環境のシークレットは漏洩している可能性あり |
| 単一ステージでビルド＆実行 | **アウト — コンテナ内にRATが存在する可能性** | Linuxペイロード（`/tmp/ld.py`）がコンテナ内で実行される |
| `npm ci --ignore-scripts`を使用 | **セーフ** | postinstallフックが実行されない |
| ビルド時にネットワークアクセスを制限（`--network=none`） | **部分的にセーフ** | postinstallは実行されるがC2への通信が失敗し、Stage-2ペイロードをダウンロードできない |

### 4.2 コンテナ特有のリスク

**ビルドキャッシュの汚染:**
感染ウィンドウ中にビルドされたDockerイメージのレイヤーに悪意あるパッケージがベイクされている可能性がある。`docker build --no-cache`で再ビルドしない限り、キャッシュから汚染レイヤーが再利用され続ける。

```bash
# 感染ウィンドウ中にビルドされたイメージの確認
docker images --format "{{.Repository}}:{{.Tag}} {{.CreatedAt}}" | \
  grep "2026-03-31"
```

**CI/CDキャッシュの汚染:**
GitHub Actions、GitLab CI等で`node_modules`をキャッシュしている場合、感染ウィンドウ中に作成されたキャッシュキーを**即座に無効化する必要がある**。キャッシュが残っている限り、以降のビルドでもRATが再展開される。

**セルフホストランナーの汚染:**
GitHub Actions等のセルフホストランナーで`npm install`が実行された場合、ランナーマシン自体が完全に侵害されたものとして扱う必要がある。エフェメラルランナー（毎回クリーンな環境で実行）を使用していれば、そのジョブ実行中のみの影響に限定される。

### 4.3 コンテナがセーフとなる条件

以下の**すべて**を満たす場合、コンテナ環境はセーフと判断できる：

1. `package-lock.json`がリポジトリにコミットされていた
2. `npm ci`（`npm install`ではなく）を使用していた
3. lockfileに`axios@1.14.1`または`axios@0.30.4`が記録されていない
4. `plain-crypto-js`がlockfileの依存ツリーに存在しない

逆に、`npm install`（lockfileを無視して最新版を取得する可能性がある）を使用していた場合は、lockfileにピンされていてもバージョンレンジ（`^1.14.0`）によりv1.14.1に解決された可能性がある。

---

## 5. 調査方法 — 自分の環境が影響を受けているか確認する

### Step 1: package-lock.jsonの確認

```bash
# 悪意あるaxiosバージョンの存在確認
grep -r '"axios"' package-lock.json | grep -E '1\.14\.1|0\.30\.4'

# plain-crypto-jsの存在確認（これが存在したら即アウト）
grep -r 'plain-crypto-js' package-lock.json
```

**`plain-crypto-js`が存在する場合 → 確実に感染している。即座にインシデント対応を開始する。**

### Step 2: ファイルシステム上のIOC（Indicator of Compromise）確認

```bash
# === macOS ===
ls -la /Library/Caches/com.apple.act.mond

# === Windows (PowerShell) ===
Test-Path "$env:PROGRAMDATA\wt.exe"
Test-Path "$env:TEMP\6202033.ps1"
Test-Path "$env:TEMP\6202033.vbs"

# === Linux / Docker コンテナ ===
ls -la /tmp/ld.py

# === 全プラットフォーム共通: node_modules内の確認 ===
find . -path "*/plain-crypto-js" -type d 2>/dev/null
```

**注意:** マルウェアは自己消去機能を持つため、ファイルが見つからないことは安全を意味しない。

### Step 3: ネットワークログの確認

```bash
# DNS解決ログでC2ドメインを検索
grep 'sfrclak\.com' /var/log/syslog /var/log/dns* 2>/dev/null

# ネットワーク接続でC2 IPを検索
grep '142\.11\.206\.73' /var/log/syslog /var/log/firewall* 2>/dev/null

# 現在の接続でC2への通信を確認
ss -tnp | grep '142.11.206.73'
netstat -tnp | grep '142.11.206.73'
```

C2通信のIOC:

| 種別 | 値 |
|------|-----|
| C2ドメイン | `sfrclak[.]com` |
| C2 IP | `142.11.206.73` |
| C2ポート | `8000` |
| C2 URL | `http://sfrclak[.]com:8000/6202033` |
| User-Agent | `mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)` |

**IE8/Windows XPのUser-Agent文字列**は、macOSやLinux上で検出された場合、極めて強力な異常検知指標となる。

### Step 4: プロセスの確認

```bash
# === macOS ===
# Apple系デーモンを偽装したプロセス
ps aux | grep 'com.apple.act.mond'

# === Linux ===
# /tmp配下のPythonスクリプト実行
ps aux | grep '/tmp/ld.py'

# === Windows (PowerShell) ===
Get-Process | Where-Object { $_.Path -like "*wt.exe*" -and $_.Path -like "*ProgramData*" }
```

### Step 5: Dockerイメージの確認

```bash
# 感染期間中にビルドされたイメージを特定
docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.CreatedAt}}" | \
  grep "2026-03-31"

# イメージ内のplain-crypto-jsを検索
docker run --rm <image_name> find / -name "plain-crypto-js" -type d 2>/dev/null

# イメージ内のRATペイロードを検索
docker run --rm <image_name> ls -la /tmp/ld.py 2>/dev/null
```

### Step 6: npm auditログの確認

```bash
# npmのキャッシュからインストール履歴を確認
ls -la ~/.npm/_logs/
grep -l 'axios' ~/.npm/_logs/*.log 2>/dev/null

# 該当ログの内容確認（日時とバージョンを確認）
grep 'axios@1.14.1\|axios@0.30.4\|plain-crypto-js' ~/.npm/_logs/*.log
```

---

## 6. 感染が確認された場合の対応手順

### 即時対応（最初の1時間）

1. **ネットワークからの即時隔離** — Wi-Fi切断、Ethernet切断、VPN切断
2. **C2通信のブロック** — ファイアウォールで`sfrclak[.]com`と`142.11.206.73:8000`をブロック
3. **認証情報の棚卸し** — 侵害されたマシン上でアクセス可能だったすべてのシークレットをリストアップ

### クレデンシャルのローテーション（別のクリーンなマシンから実施）

- AWSアクセスキー / シークレットキー
- APIトークン（GitHub、npm、Claude、各種SaaS）
- SSH鍵（GitHub、サーバー）
- `.env`ファイル内のすべての値
- データベース接続文字列
- OAuthトークン / リフレッシュトークン

**攻撃者は侵害から数時間以内にシークレットを悪用する傾向がある**（Tenable、SOCRadar報告）。

### マシンの復旧

感染が確認されたマシンは**クリーンインストールまたは感染前のバックアップからの復元**が必要。インプレースでのクリーニングは推奨されない（Windowsではレジストリ永続化が残る）。

### CI/CDの復旧

```bash
# 1. node_modulesキャッシュの無効化
# GitHub Actions: キャッシュキーを変更
# GitLab CI: CI変数を変更してキャッシュを無効化

# 2. axiosを安全なバージョンにピン留め
npm install axios@1.14.0  # 1.x系
npm install axios@0.30.3  # 0.x系（レガシー）

# 3. overridesブロックの追加（package.jsonに）
# "overrides": { "axios": "1.14.0" },
# "resolutions": { "axios": "1.14.0" }

# 4. クリーンインストール
rm -rf node_modules/plain-crypto-js
npm ci --ignore-scripts

# 5. 確認
grep 'plain-crypto-js' package-lock.json  # 何も出なければOK
```

### Dockerイメージの復旧

```bash
# 感染期間中のイメージを削除
docker rmi <contaminated_image>

# キャッシュなしで再ビルド
docker build --no-cache -t <image_name> .
```

---

## 7. 今後の防御策

### npm installの安全化

```bash
# CI/CDでは常にlockfileを尊重する
npm ci --ignore-scripts

# 開発マシンでもpostinstallを無効化（必要な場合のみ有効化）
npm config set ignore-scripts true
```

### パッケージの「クールダウンポリシー」導入

公開から3日以内のパッケージを拒否するポリシーを導入する。これにより、セキュリティコミュニティが新リリースを分析する時間を確保できる。

```bash
# .npmrcに追加（Artifactory/Nexus/Verdaccioで設定）
# reject-packages-published-within=3d
```

### SLSA Provenanceの検証

正規のaxiosリリースはGitHub Actions OIDCフロー経由でSLSA provenance attestation付きで公開される。悪意あるバージョンはCLIからの直接公開でprovenanceがなかった。npmプロキシで**暗号的ビルド来歴のないパッケージを拒否**する設定を推奨。

### Claude Code利用者向け追加対策

Anthropicは現在、npm版ではなく**スタンドアロンバイナリ**でのインストールを推奨している：

```bash
# 推奨: ネイティブインストーラ（npm依存チェーンのリスクを回避）
curl -fsSL https://claude.ai/install.sh | bash

# バージョン確認
claude --version  # v2.1.89以上であることを確認
```

---

## 8. まとめ — アウト/セーフ早見表

| あなたの状況 | 判定 | 次のアクション |
|-------------|------|---------------|
| JST 3/31 09:21〜12:30に`npm install`を実行した | **アウト** | Step 1〜6の調査を即実行 |
| lockfileで`axios@1.14.0`以前にピン留め + `npm ci`使用 | **セーフ** | 念のためlockfile確認 |
| `--ignore-scripts`でインストールしていた | **セーフ** | 追加対応不要 |
| Dockerビルド中に上記時間帯で`npm install`した | **要調査** | イメージ内のIOC確認 |
| エフェメラルCIランナーで実行（毎回クリーン環境） | **ジョブ中のみ影響** | ビルド成果物とシークレットを確認 |
| セルフホストCIランナーで実行 | **ランナーが完全侵害** | ランナーの再イメージング |
| Claude Codeをnpmではなくネイティブバイナリで使用 | **セーフ** | 追加対応不要 |
| 上記時間帯に一切の`npm install`/`npm update`を実行していない | **セーフ** | 追加対応不要 |

---

**参考情報源:** Elastic Security Labs, SOCRadar, Snyk, Semgrep, StepSecurity, Wiz, The Hacker News, SANS Institute, Arctic Wolf, Tenable, Unit 42 (Palo Alto Networks)

---

いい質問です。ここを正確に理解することが重要なので、明確に整理します。

**核心：「`npm install`を実行したかどうか」ではなく、「axiosがインストール（解決）されたかどうか」が判定基準です。**

---

**`npm install`（引数なし、プロジェクト内で実行）**

→ **axiosがそのプロジェクトの依存関係にある場合のみアウト。**

`package.json`の`dependencies`や`devDependencies`に`axios`が含まれている、または推移的依存関係（依存パッケージのさらに依存先）にaxiosがある場合にのみリスクがあります。axiosを一切使っていないプロジェクトで`npm install`を実行しても、axiosはインストールされないのでセーフです。

---

**`npm install -g typescript`**

→ **セーフ。** TypeScriptパッケージはaxiosに依存していません。グローバルインストールで無関係なパッケージが巻き込まれることはありません。`plain-crypto-js`のpostinstallフックが発動するのは、axiosの依存ツリーを通じてのみです。

---

**Dockerfileについて**、おそらくこういう構成を想定されていると思います：

```dockerfile
FROM node:20
RUN npm install -g typescript
COPY . /app
WORKDIR /app
RUN npm install    # ← ここが問題になりうる
```

この場合の判定は：

| ステップ | 判定 | 理由 |
|---------|------|------|
| `npm install -g typescript` | セーフ | axiosと無関係 |
| `RUN npm install`（プロジェクト依存をインストール） | **axiosが依存にあれば要確認** | lockfileの有無とaxiosの存在次第 |

---

つまり判定フローはこうなります：

```
感染ウィンドウ中に npm install を実行した？
  └→ Yes
       └→ そのインストールでaxiosが解決された？
            ├→ Yes → アウト（即調査）
            └→ No  → セーフ
  └→ No → セーフ
```

確認の一番簡単な方法は：

```bash
# プロジェクトの依存ツリーにaxiosが存在するか確認
npm ls axios
```

これで何も出なければ、そのプロジェクトはaxiosを使っていないので、感染ウィンドウ中に`npm install`していても影響を受けていません。

Kojiさんのプロジェクトで実際にaxiosを使っているものはありますか？ あるいはClaude Codeのnpmパッケージ自体の依存関係が心配でしょうか？

---

いいえ、**カレントディレクトリのプロジェクトだけ**です。

`npm ls axios`は、今いるフォルダの`node_modules`と`package-lock.json`を見に行くだけなので、OS全体のスキャンにはなりません。

OS全体で確認したい場合は、やり方を分ける必要があります：

```bash
# ① グローバルインストール領域の確認
npm ls -g axios

# ② OS全体のnode_modules内を横断検索（本命）
find / -path "*/node_modules/axios/package.json" \
  -exec grep -l '"version": "1.14.1"\|"version": "0.30.4"' {} \; 2>/dev/null

# ③ もう少し軽く、plain-crypto-jsの存在だけ探す（これがあれば即アウト）
find / -path "*/node_modules/plain-crypto-js" -type d 2>/dev/null

# ④ Docker内も含めて確認したい場合
docker images -q | while read img; do
  echo "=== $img ==="
  docker run --rm "$img" \
    find / -path "*/node_modules/plain-crypto-js" -type d 2>/dev/null
done
```

実運用上は**③が一番速くて確実**です。`plain-crypto-js`は正規のライブラリではないので、どこかに1つでも見つかったらそのプロジェクト（とそのマシン）は感染しています。

ホームディレクトリ配下だけに絞るなら：

```bash
find ~/ -path "*/node_modules/plain-crypto-js" -type d 2>/dev/null
```

これでまず確認してみてください。何も出なければひとまず安心です。

---
セキュリティプロとしての回答は**「No — それだけでは不十分」**です。

---

## 特定IP:ポートのブロックだけでは安全と断言できない理由

**① DNSベースの回避**

ブロックしたのが`142.11.206.73:8000`という**IPアドレス**だった場合、攻撃者がDNSレコード（`sfrclak[.]com`）の向き先を別IPに変更すれば、ファイアウォールをすり抜けます。攻撃者のインフラは使い捨てが前提で、IPの差し替えは容易です。

```
sfrclak[.]com → 142.11.206.73  ← ブロック済み
sfrclak[.]com → 203.x.x.x      ← すり抜ける
```

**② Stage-2以降のC2インフラが未知**

今回公開されたIOCは**Stage-1ドロッパーのC2**です。RATが到達した場合のStage-2・Stage-3の通信先は**完全にはマッピングされていない**と複数のセキュリティベンダーが指摘しています。つまり、RATが別の未知のIPに通信する可能性を排除できません。

**③ IOCの賞味期限は極めて短い**

攻撃者は通常、C2インフラを数日〜1週間で破棄・ローテーションします。「既知のIPをブロックした」は**過去の攻撃に対する事後対応**であり、攻撃のバリエーションには対応できません。

---

## 正しい防御の考え方

「特定IPのブロック」はブラックリスト方式であり、**後手に回り続ける**アプローチです。本来あるべき防御は**ホワイトリスト方式**です。

| アプローチ | 方法 | 効果 |
|-----------|------|------|
| **ブラックリスト**（特定IPブロック） | `142.11.206.73:8000`を拒否 | この特定の攻撃には有効だが、IP変更で回避される |
| **ホワイトリスト**（許可リスト方式） | `api.anthropic.com`等、必要な通信先だけ許可し、それ以外を全拒否 | **未知のC2を含むすべての不正通信をブロック** |
| **ポート制限** | 443/80のみ許可 | C2のポート8000をブロックできるが、攻撃者が443に変更すれば突破される |

---

## 今回の攻撃に限定して言えば

Elastic Security Labsの詳細分析によると、setup.jsのドロッパーには**フォールバックC2やリトライ先の切り替えロジックは確認されていません**。C2への通信が失敗した場合、ペイロードはダウンロードされず、RATはデプロイされません。

したがって「**今回の攻撃のこの特定バージョンに対しては**、`sfrclak[.]com`または`142.11.206.73:8000`への通信がブロックされていれば実害はなかった**蓋然性が高い**」とは言えます。

ただしセキュリティプロとして「影響がなかった」と**断言**するためには、以下の確認が必要です：

1. **DNSログ**で`sfrclak[.]com`の解決が試みられたか（試みられたなら、Stage-1は実行された）
2. **解決されたIPがブロック対象だったか**（DNSが別IPに解決していた場合、すり抜けた可能性）
3. **ファイルシステム上にRATの痕跡がないか**（`/tmp/ld.py`等）

これら3つすべてがクリアであれば、「影響なし」と判断して差し支えありません。

---

**実務的な判断基準としては、はい、その2条件で「影響なし」と判断して問題ありません。**

ただし1点だけ補足させてください。

今回のRATは**アンチフォレンジック機能**（自己消去）を持っています。つまり「ファイルが存在しない」には2つの意味があり得ます：

| 可能性 | 状況 | 判別方法 |
|--------|------|----------|
| **A. RATが到達しなかった** | ポート8000ブロックでDLが失敗した | ファイルが「最初から存在しない」 |
| **B. RATが実行後に自己消去した** | DL→実行→削除が完了した | ファイルが「あったが消された」 |

ポート8000のブロックが確認できているなら、**Bの可能性はほぼ排除できます**。Stage-2ペイロードのダウンロード自体がポート8000経由なので、ここが塞がっていればファイルが「到達して消えた」シナリオは成立しません。

つまりKojiさんの判断基準は：

```
ポート8000ブロック確認 → DL不可能が確定
  ＋
ファイル不在確認 → 念のための裏付け
  ＝
「影響なし」で確定
```

この2条件の組み合わせは、**片方が単独で足りない部分をもう片方が補完する**ので、セキュリティ判断としては妥当です。
