# Trivyサプライチェーン攻撃（TeamPCP）詳細レポート

**作成日:** 2026年4月6日  
**CVE:** CVE-2026-33634（CVSS 9.4）  
**脅威アクター:** TeamPCP（別名: DeadCatx3, PCPcat, PersyPCP, ShellForce, CipherForce）  
**影響範囲:** Trivyバイナリ、GitHub Actions（trivy-action / setup-trivy）、Docker Hub イメージ、および下流プロジェクト（LiteLLM、Checkmarx KICS、60+のnpmパッケージ）  
**CISAカタログ登録:** 2026年3月26日（Known Exploited Vulnerabilities Catalog）

---

## 1. エグゼクティブサマリー

2026年3月19日、クラウドネイティブ環境で最も広く使われているオープンソース脆弱性スキャナ「Trivy」（Aqua Security）が、脅威アクター「TeamPCP」により多段階サプライチェーン攻撃を受けた。攻撃者はCI/CDワークフローの設定ミスを悪用して取得した認証情報を使い、GitHub Actions、リリースバイナリ、Docker Hubイメージを同時に侵害した。

この攻撃は単独の事件ではなく、**5つのエコシステム（GitHub Actions、Docker Hub、npm、OpenVSX、PyPI）にまたがる連鎖型キャンペーン**の起点である。Trivyから窃取された認証情報は、Checkmarx KICS、60以上のnpmパッケージ（CanisterWorm）、LiteLLM、Telnyxの侵害に使用された。

SANSは「セキュリティツールへのサプライチェーン攻撃としては、公式に文書化された中で最も高度なもの」と評価している。

**セキュリティスキャナは設計上、広範な権限でCI/CD環境にアクセスする。スキャナが侵害されると、組織がセキュリティのために付与した権限そのものが攻撃者に継承される。最も熱心にスキャンを実行していた組織が、最も大きな影響を受けた。**

---

## 2. 攻撃タイムライン

### 2.1 全体タイムライン

| 日付（UTC） | JST | フェーズ | イベント |
|------------|-----|---------|---------|
| 2月末 | — | Phase 0 | ボット「MegaGame10418」がTrivyの`pull_request_target`ワークフロー設定ミスを悪用し、`aqua-bot`サービスアカウントのPATを窃取 |
| 3/1 | — | 初回対応 | Aqua SecurityがPAT侵害を開示、認証情報をローテーション。**ただしローテーションが不完全（非アトミック）で、攻撃者が残存アクセスを維持** |
| 3/4 | — | 潜伏 | 攻撃者がTrivyリポジトリに偽装コミット（`1885610c`）を送信。`actions/checkout`のSHAを悪意あるorphanコミット（`70379aad`）に差し替え、GoReleaserの`--skip=validate`を追加 |
| **3/19 17:43** | **3/20 02:43** | **Phase 1** | **`trivy-action`の76/77バージョンタグを悪意あるコミットに強制プッシュ。`setup-trivy`の全7タグも同様に侵害** |
| 3/19 18:22 | 3/20 03:22 | Phase 2 | Trivy v0.69.4バイナリをGitHub Releases、GHCR、ECR Public、Docker Hubに公開 |
| 3/19 21:42 | 3/20 06:42 | 対応開始 | Trivyチームが悪意あるバイナリを除去 |
| 3/20 05:40 | 3/20 14:40 | 対応 | trivy-actionの悪意あるタグを修正 |
| **3/20 20:45** | **3/21 05:45** | **Phase 3** | **窃取されたnpmトークンを使い、CanisterWormを60以上のnpmパッケージにデプロイ。28パッケージを60秒未満で侵害** |
| 3/22 16:00 | 3/23 01:00 | Phase 4 | Docker Hubに悪意あるTrivyイメージv0.69.5、v0.69.6を公開。`latest`タグも汚染 |
| 3/22 20:31 | 3/23 05:31 | 追加攻撃 | Aquaの44内部リポジトリ（aquasec-com組織）を改ざん |
| 3/23 | 3/23-24 | Phase 5 | Checkmarx KICSおよびOpenVSX拡張機能を侵害 |
| **3/24 10:39** | **3/24 19:39** | **Phase 6** | **Trivyスキャンから窃取した認証情報でLiteLLM v1.82.7/v1.82.8をPyPIに公開** |
| 3/25 | 3/25-26 | 最新情報 | TeamPCPが約300GBの窃取認証情報を使い、LAPSUS$と連携して恐喝活動を開始との報道 |
| 3/27 | 3/27-28 | Phase 7 | Telnyx PyPIパッケージ（v4.87.1/v4.87.2）を侵害 |

### 2.2 コンポーネント別の侵害ウィンドウ（JST）

| コンポーネント | 侵害開始（JST） | 侵害終了（JST） | 影響時間 |
|--------------|----------------|----------------|---------|
| `trivy-action`（76タグ） | 3/20 02:43 | 3/20 14:40 | **約12時間** |
| `setup-trivy`（7タグ） | 3/20 02:43 | 3/20 06:44 | **約4時間** |
| Trivyバイナリ v0.69.4 | 3/20 03:22 | 3/20 06:42 | **約3時間** |
| Docker Hub v0.69.4 | 3/20 03:22 | 3/20 06:42 | **約3時間** |
| Docker Hub v0.69.5/v0.69.6 | 3/23 01:00 | 除去時期不明 | — |

---

## 3. 攻撃手法の技術的詳細

### 3.1 初期アクセス：pull_request_target の悪用

攻撃の起点は、Trivyリポジトリの`pull_request_target`ワークフロー設定ミスだった。`pull_request_target`トリガーは、フォークからのPRに対してもターゲットリポジトリのシークレットにアクセスできる権限を持つ。攻撃者はこの設定を悪用し、PRからAqua SecurityのサービスアカウントPATを窃取した。

### 3.2 タグポイズニング：バージョンタグの強制プッシュ

GitHub Actionsで`uses: aquasecurity/trivy-action@v0.34.2`のようにバージョンタグで参照する場合、Gitタグは単なるコミットSHAへのポインタであり、書き換え可能。攻撃者は有効な認証情報を使い、76/77のバージョンタグを悪意あるコミットに`git push --force`で書き換えた。

**重要：GitHubの「Immutable」リリースバッジは、タグの強制プッシュを防止しない。** v0.35.0のみが3月4日にImmutable Releaseとして公開されたため、書き換えを免れた。

各悪意あるコミットは以下の偽装を行っていた：
- 元のリリース日を装ったコミット日付（例：2021年、2022年の日付）
- 正規メンテナーの名前を偽装（DmitriyLewen、rauchg）
- 変更は`entrypoint.sh`のみ（元のタグは複数ファイルを変更していた）
- 親コミットが2026年3月のものであることから、日付の偽装が判明

### 3.3 ペイロード：3段階の認証情報窃取

**Stage 1：メモリダンプによるシークレット収集**

悪意あるコードは正規のTrivyスキャンの**前に**実行された。そのためパイプラインは正常に完了したように見え、スキャン結果も正常に表示された。

GitHub Actionsランナーの親プロセスのメモリ空間を完全にダンプする手法を使用。GitHub Actionsの`isSecret:true`マーキングは標準出力のスクラビングに依存しているため、プロセスメモリからの直接読み取りでバイパスされた。

収集対象：
- 環境変数（すべてのパイプラインシークレット含む）
- SSH鍵・設定ファイル
- AWS/GCP/Azure認証情報
- Kubernetesトークン
- Docker設定ファイル
- git認証情報
- 暗号資産ウォレット（Solanaバリデーターキーペア含む）
- シェル履歴

**Stage 2：暗号化とデータ送信**

収集データはAES-256-CBC + RSA-4096ハイブリッド暗号で暗号化後、タイポスクワッティングドメイン`scan.aquasecurtiy[.]org`（正規の`aquasecurity.org`を偽装、IP: 45.148.10.212）にHTTPS POSTで送信。

**フォールバック機構：** C2サーバーへの送信が失敗した場合、被害者の`GITHUB_TOKEN`を使い、GitHub上に`tpcp-docs`という公開リポジトリを作成し、窃取データをリリースアセットとしてアップロード。GitHubをデータ送信チャネルとして悪用するという手法。

**Stage 3：永続化（開発者マシンの場合）**

CI/CDランナーではなく開発者のローカルマシンでTrivyバイナリが実行された場合（`GITHUB_ACTIONS != "true"`を確認）、以下の永続化メカニズムをインストール：

- バックドア：`~/.config/systemd/user/sysmon.py`
- systemdユニット：PostgreSQLツールやシステムモニタリングとして偽装
- 5分の初期遅延後、50分ごとにICP（Internet Computer Protocol）ブロックチェーンカニスター（`tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io`）をポーリング
- C2レスポンスに「youtube.com」が含まれる場合はキルスイッチ発動
- 新しいURLからバイナリを`/tmp/pglog`にダウンロードして実行

**ICP（ブロックチェーン）ベースのC2はドメインレジストラやホスティングプロバイダによるテイクダウンが不可能であり、サプライチェーン攻撃での初の使用事例として注目されている。**

### 3.4 CanisterWorm：自己伝播型npmワーム

Trivyから窃取されたnpmトークンを使い、攻撃者は**CanisterWorm**と呼ばれる自己伝播型ワームをnpmエコシステムにデプロイした。

- 28の`@emilgroup`パッケージを60秒未満で侵害
- `@opengov`（16パッケージ）、`@teale.io/eslint-config`、`@airtm/uuid-base32`等にも展開
- 合計60以上のnpmパッケージが侵害
- 後期バリアントはpostinstallフックにnpmトークン窃取機能を追加し、感染パッケージをインストールした開発者のnpmアカウントからさらに伝播

---

## 4. 影響判定：アウト or セーフ

### 4.1 使用方法別の判定

| 使用方法 | 判定 | 理由 |
|---------|------|------|
| `uses: aquasecurity/trivy-action@v0.34.2`等のタグ参照 | **3/20 02:43-14:40（JST）に実行していたらアウト** | 76/77タグが書き換えられた |
| `uses: aquasecurity/trivy-action@v0.35.0` | **セーフ** | Immutable Releaseで保護された唯一のタグ |
| `uses: aquasecurity/trivy-action@57a97c7...`（SHA固定） | **セーフ**（安全なコミットの場合） | SHAは書き換え不可能 |
| `docker run aquasec/trivy`（タグなし） | **3/20 03:22-06:42に実行していたらアウト** | `latest`が汚染されていた |
| `docker run aquasec/trivy:0.69.4` | **アウト** | 悪意あるバイナリ |
| `docker run aquasec/trivy:0.69.5` / `:0.69.6` | **アウト** | 3/22に追加公開された悪意あるイメージ |
| `docker run aquasec/trivy:0.69.3`以前 | **セーフ** | 侵害前のバージョン |
| `docker run aquasec/trivy@sha256:<digest>`（digest固定） | **安全なdigestであればセーフ** | digest書き換え不可能 |
| Aqua Platformの商用製品内のTrivy | **セーフ** | Aqua公式声明で影響なしと確認 |

### 4.2 安全なバージョン

| コンポーネント | 安全なバージョン | コミットSHA |
|--------------|----------------|------------|
| trivy-action | v0.35.0 | `57a97c7e7821a5776cebc9bb87c984fa69cba8f1` |
| setup-trivy | v0.2.6 | `3fb12ec` |
| Trivyバイナリ | v0.69.3以前 | — |

---

## 5. 感染確認手順

### Step 1：GitHub Actionsワークフローの確認

```bash
# リポジトリ内のtrivy参照を検索
grep -r 'aquasecurity/trivy' .github/workflows/

# タグ参照（危険）かSHA参照（安全）かを確認
# ❌ @v0.34.2 のようなタグ参照 → 要確認
# ✅ @57a97c7... のようなSHA参照 → セーフ
```

### Step 2：侵害ウィンドウ中の実行確認

```bash
# GitHub CLIで3/19-20のワークフロー実行を確認
gh run list --workflow=<ワークフロー名> \
  --created="2026-03-19..2026-03-21" \
  --json startedAt,status,conclusion,name

# trivy-actionのログ内で侵害SHA参照を検索
gh run view <RUN_ID> --log | grep -i 'trivy'
```

### Step 3：tpcp-docsリポジトリの確認（データ窃取の痕跡）

```bash
# 組織内のtpcp-docsリポジトリを検索
gh repo list <ORG名> --json name -q '.[].name' | grep tpcp-docs

# 個人アカウントでも確認
gh repo list --json name -q '.[].name' | grep tpcp-docs
```

**`tpcp-docs`リポジトリが存在する場合、認証情報のデータ送信が成功しており、全シークレットが侵害されている。**

### Step 4：Dockerイメージの確認

```bash
# ローカルのtrivyイメージを確認
docker images aquasec/trivy --format "{{.Repository}}:{{.Tag}} {{.ID}} {{.CreatedAt}}"

# 悪意あるバージョンの存在確認
docker images aquasec/trivy --format "{{.Tag}}" | grep -E '0\.69\.[456]'
```

### Step 5：開発者マシンの永続化確認

```bash
# systemdバックドアの確認
ls -la ~/.config/systemd/user/sysmon.py 2>/dev/null
ls -la ~/.config/systemd/user/sysmon.service 2>/dev/null
systemctl --user status sysmon.service 2>/dev/null

# 追加の永続化名称（バリアント）
systemctl --user list-units | grep -E 'sysmon|pgmon|pgmonitor|internal-monitor'

# ペイロードファイル
ls -la /tmp/pglog /tmp/.pg_state 2>/dev/null
```

### Step 6：Kubernetes環境の確認

```bash
# TeamPCPのDaemonSetを検索
kubectl get daemonsets -n kube-system | grep -E 'host-provisioner-std|host-provisioner-iran'

# 不審なPodを検索
kubectl get pods -n kube-system | grep -E 'node-setup|host-provisioner'
```

### Step 7：ネットワーク通信の確認

```bash
# C2ドメインへの通信痕跡
grep -rE 'scan\.aquasecurtiy\.org|45\.148\.10\.212' /var/log/ 2>/dev/null

# Cloudflare Tunnel C2
grep -r 'plug-tab-protective-relay\.trycloudflare\.com' /var/log/ 2>/dev/null

# ICP C2
grep -r 'tdtqy-oyaaa-aaaae-af2dq-cai' /var/log/ 2>/dev/null
```

---

## 6. IOC一覧

### ネットワークIOC

| 種別 | 値 | 用途 |
|------|-----|------|
| C2ドメイン（主） | `scan.aquasecurtiy[.]org` | データ送信先（タイポスクワット） |
| C2 IP | `45.148.10.212` | C2サーバー（アムステルダム） |
| C2ドメイン（Cloudflare） | `plug-tab-protective-relay.trycloudflare[.]com` | 追加認証情報の窃取 |
| C2（ICP） | `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io` | 分散型C2（テイクダウン不能） |
| LiteLLM C2 | `models.litellm[.]cloud` | LiteLLM攻撃のデータ送信先 |
| Checkmarx C2 | `checkmarx[.]zone` | 永続化バックドアのペイロード取得 |

### ファイルシステムIOC

| パス | 用途 |
|------|------|
| `~/.config/systemd/user/sysmon.py` | バックドアドロッパー |
| `~/.config/systemd/user/sysmon.service` | systemd永続化ユニット |
| `/tmp/pglog` | ダウンロードされたペイロード |
| `/tmp/.pg_state` | ポーリング状態ファイル |

### GitHub IOC

| 指標 | 意味 |
|------|------|
| `tpcp-docs`または`tpcp-docs-*`リポジトリの存在 | フォールバック経由でのデータ送信成功 |
| コミットメッセージに「teampcp update」 | 侵害されたアカウントからの操作 |

### 侵害されたコミットSHA

| SHA | リポジトリ |
|-----|-----------|
| `70379aad1a8b40919ce8b382d3cd7d0315cde1d0` | actions/checkout（orphanコミット） |
| `1885610c6a34811c8296416ae69f568002ef11ec` | aquasecurity/trivy（偽装コミット） |
| `8afa9b9` | aquasecurity/setup-trivy（悪意あるコミット） |

---

## 7. 感染が確認された場合の対応

### 7.1 即時対応

1. **全パイプラインシークレットの即時ローテーション**（最優先）
   - GitHub Token（GITHUB_TOKEN、PAT）
   - クラウドプロバイダー認証情報（AWS/GCP/Azure）
   - コンテナレジストリトークン（Docker Hub、GHCR、ECR）
   - SSH鍵
   - npm/PyPIトークン
   - データベースパスワード
   - APIキー（すべて）

2. **ローテーションはアトミックに実施** — 古い認証情報を先に無効化し、新しい認証情報を発行する。Aqua Securityの最初のインシデント対応が失敗した原因は、ローテーションが非アトミック（古い認証情報と新しい認証情報が同時に有効な期間が存在した）だったことにある。

3. **C2ドメインのブロック**

```bash
# ファイアウォールルールに追加
scan.aquasecurtiy[.]org
45.148.10.212
plug-tab-protective-relay.trycloudflare[.]com
checkmarx[.]zone
models.litellm[.]cloud
```

### 7.2 修復

```yaml
# GitHub Actionsワークフローの修正
# ❌ タグ参照（書き換え可能）
- uses: aquasecurity/trivy-action@v0.34.2

# ✅ SHA固定（書き換え不可能）
- uses: aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1
```

```bash
# Docker イメージの修正
# ❌ タグ参照
docker run aquasec/trivy:latest

# ✅ digest固定
docker pull aquasec/trivy:0.69.3
DIGEST=$(docker inspect aquasec/trivy:0.69.3 --format '{{index .RepoDigests 0}}')
docker run $DIGEST image <対象>
```

### 7.3 開発者マシンの修復

```bash
# 永続化メカニズムの除去
systemctl --user stop sysmon.service 2>/dev/null
systemctl --user disable sysmon.service 2>/dev/null
rm -rf ~/.config/sysmon/
rm -f ~/.config/systemd/user/sysmon.service
rm -f /tmp/.pg_state /tmp/pglog
systemctl --user daemon-reload
```

影響が確認された場合は、クリーンインストールまたは感染前バックアップからの復元を推奨。

---

## 8. 根本対策

### 8.1 すべてのGitHub ActionsをSHA固定に

```bash
# pinact で既存ワークフローを一括変換
npx pinact .github/workflows/*.yml

# Renovate で自動的にSHA固定を維持
# renovate.json
{
  "pinGitHubActionDigests": true
}
```

### 8.2 pull_request_target ワークフローの監査

自組織のリポジトリで`pull_request_target`トリガーを使用しているワークフローを確認し、フォークからのコードチェックアウトを行っていないか確認する。このトリガーは安全に使用することが極めて難しく、可能であれば避けるべき。

### 8.3 CI/CDランナーのネットワーク制限

StepSecurity Harden-RunnerやGitHub Actions のネットワークポリシーを使い、CI/CDランナーからのアウトバウンド通信をホワイトリスト方式で制限する。Trivy攻撃では`scan.aquasecurtiy[.]org`へのアウトバウンド通信がHarden-Runnerにより検出・フラグされた。

### 8.4 認証情報ローテーションの原則

認証情報のローテーションは**アトミック**に実施する。古い認証情報を無効化してから新しい認証情報を発行する。旧認証情報と新認証情報が同時に有効な期間を一切作らない。Trivyのインシデントは、この原則が守られなかったことで2回目の攻撃を許した。

---

## 9. この事件が示す教訓

### セキュリティツールそのものが攻撃対象

Trivy（脆弱性スキャナ）、Checkmarx KICS（IaCスキャナ）、LiteLLM（LLMゲートウェイ）は、いずれも設計上、広範な権限で動作するツールである。攻撃者がこれらを標的にしたのは合理的な選択で、ツールが本来持つ権限がそのまま攻撃者に継承される。

### バージョンタグは信頼できない

Gitのタグは可変ポインタであり、コミットSHAのみが不変。GitHub Actionsの`@v1`や`@v0.34.2`のようなタグ参照は、今回の攻撃で76/77タグが書き換えられたことで、その危険性が実証された。

### 不完全なインシデント対応は新たな攻撃を招く

Aqua Securityは3月1日に最初の侵害を認識して対応したが、認証情報のローテーションが不完全だったため、攻撃者は残存アクセスを維持し、3月19日の本格攻撃を実行した。

---

## 10. 参考リンク

### 公式情報

- **Aqua Security公式インシデントレポート:** https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/
- **GitHub Security Advisory (GHSA-69fq-xp46-6x23):** https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23
- **CVE-2026-33634（Tenable）:** https://www.tenable.com/cve/CVE-2026-33634
- **CISA KEVカタログ登録:** https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-33634
- **Trivy GitHub Discussion #10425:** https://github.com/aquasecurity/trivy/discussions/10425

### セキュリティベンダー分析

- **Wiz Research（初期分析・TeamPCP追跡）:** https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack
- **SANS Institute（キャンペーン全体分析）:** https://www.sans.org/blog/when-security-scanner-became-weapon-inside-teampcp-supply-chain-campaign
- **Palo Alto Unit 42 / Cortex Cloud:** https://www.paloaltonetworks.com/blog/cloud-security/trivy-supply-chain-attack/
- **Snyk（GitHub Actions侵害詳細）:** https://snyk.io/articles/trivy-github-actions-supply-chain-compromise/
- **Socket.dev（タグポイズニング分析）:** https://socket.dev/blog/trivy-under-attack-again-github-actions-compromise
- **StepSecurity（IOC検出・修復手順）:** https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release
- **Legit Security（対応プレイブック）:** https://www.legitsecurity.com/blog/the-trivy-supply-chain-compromise-what-happened-and-playbooks-to-respond
- **SafeDep（統合タイムライン）:** https://safedep.io/trivy-teampcp-supply-chain-compromise/
- **Kaspersky:** https://www.kaspersky.com/blog/critical-supply-chain-attack-trivy-litellm-checkmarx-teampcp/55510/
- **NHS England:** https://digital.nhs.uk/cyber-alerts/2026/cc-4758
- **CVE Reports（技術詳細）:** https://cvereports.com/reports/CVE-2026-33634

### 下流攻撃（Trivyから連鎖）

- **LiteLLM攻撃 — Trend Micro:** https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html
- **LiteLLM攻撃 — Endor Labs:** https://www.endorlabs.com/learn/teampcp-isnt-done
- **CanisterWorm（npmワーム）— Semgrep:** https://semgrep.dev/blog/2026/the-teampcp-credential-infostealer-chain-attack-reaches-pythons-litellm/
- **12日間5件の統合分析 — DreamFactory:** https://blog.dreamfactory.com/five-supply-chain-attacks-in-twelve-days-how-march-2026-broke-open-source-trust-and-what-comes-next
- **Microsoft Security Blog:** https://www.microsoft.com/en-us/security/blog/2026/03/24/detecting-investigating-defending-against-trivy-supply-chain-compromise/
