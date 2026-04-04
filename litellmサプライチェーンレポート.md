# LiteLLMサプライチェーン攻撃（TeamPCP）詳細レポート

**作成日:** 2026年4月5日  
**CVE:** CVE-2026-33634（CVSS 9.4）  
**脅威アクター:** TeamPCP  
**影響バージョン:** litellm 1.82.7 / 1.82.8（PyPI配布のみ）  
**安全バージョン:** 1.82.6以前、および1.83.0以降  
**公式Dockerイメージ（ghcr.io/berriai/litellm）：影響なし**

---

## 1. エグゼクティブサマリー

2026年3月24日、AIインフラパッケージ「LiteLLM」（月間9,500万ダウンロード超）のPyPIパッケージが、脅威アクター「TeamPCP」により侵害された。攻撃者はLiteLLMのCI/CDパイプラインで使用されていた脆弱性スキャナ「Trivy」の事前侵害を通じてPyPI公開用認証情報を窃取し、バックドア入りのv1.82.7およびv1.82.8をPyPIに直接アップロードした。

悪意あるパッケージは3段階のペイロードを実行する設計で、認証情報の大規模収集、Kubernetes環境での横展開、systemdバックドアによる永続化を行う。PyPIでの公開時間は約3時間だったが、1日340万ダウンロードという規模を考えると、相当数の環境が影響を受けた可能性がある。

**重要：公式LiteLLM Dockerイメージ（`ghcr.io/berriai/litellm`）は影響を受けていない。** Dockerイメージはrequirements.txtで依存関係をピン留めしてGitHubソースからビルドされており、PyPIの最新版を動的に取得する仕組みではないため、侵害されたPyPIパッケージは一切含まれていない。

---

## 2. 攻撃の連鎖：Trivyからの横展開

今回の攻撃は単独の事件ではなく、2026年2月末から3月にかけてTeamPCPが実行した**多段階サプライチェーンキャンペーン**の一環である。

### 2.1 攻撃チェーンのタイムライン

| 日付（UTC） | フェーズ | イベント |
|------------|---------|---------|
| 2月末 | Phase 1 | TeamPCPのボット「MegaGame10418」がTrivyのCI/CDワークフロー設定ミス（`pull_request_target`トリガー）を悪用し、Aqua Securityの`aqua-bot` PATを窃取 |
| 3/19 | Phase 2 | Trivyの76/77バージョンタグを悪意あるコミットに強制プッシュ。Docker Hub/GHCR/ECRにも侵害済みバイナリ（v0.69.4）を公開 |
| 3/23 | Phase 3 | Checkmarx KICS GitHub Actionを同様に侵害 |
| 3/23 | Phase 4 | OpenVSX拡張機能（cx-dev-assist 1.7.0、ast-results）を侵害 |
| **3/24 10:39** | **Phase 5** | **LiteLLM v1.82.7をPyPIに公開（proxy_server.pyへのコード注入）** |
| **3/24 10:52** | **Phase 6** | **LiteLLM v1.82.8をPyPIに公開（.pthファイル追加による攻撃強化）** |
| 3/24 ~12:44 | 対応 | PyPIが悪意あるバージョンを隔離・除去 |
| 3/27 | Phase 7 | Telnyx PyPIパッケージ（v4.87.1/v4.87.2）を同様の手法で侵害 |

### 2.2 Trivyからの認証情報窃取の流れ

LiteLLMのCI/CDパイプラインはセキュリティスキャンにTrivyを使用していた。Trivyが侵害されたことで、パイプライン実行時に`PYPI_PUBLISH`トークンが攻撃者に送信された。攻撃者はこのトークンを使い、GitHubのリリースプロセスを完全にバイパスし、PyPIに直接パッケージをアップロードした。

GitHubリポジトリのソースコードは一切改変されておらず、悪意あるコードはPyPI配布物にのみ存在した。

---

## 3. 感染ウィンドウ（日本時間）

| JST | UTC | イベント |
|-----|-----|---------|
| **3/24 19:39** | 10:39 | `litellm@1.82.7` PyPIに公開 — 感染ウィンドウ開始 |
| **3/24 19:52** | 10:52 | `litellm@1.82.8` PyPIに公開（.pth追加） |
| **3/24 21:44頃** | 12:44頃 | PyPIがパッケージを隔離 — 感染ウィンドウ終了 |
| 3/25 01:00頃 | 16:00 | LiteLLMチームが全リリースを一時停止、認証情報のローテーションを実施 |

2つの悪意あるリリースの間隔はわずか13分で、v1.82.8で.pthインジェクションが追加されたことは、攻撃者が攻撃ウィンドウ中にアクティブに手法を改良していたことを示す。

---

## 4. 攻撃手法の技術的詳細

### 4.1 2つのバージョンの違い

| | v1.82.7 | v1.82.8 |
|---|---------|---------|
| 注入箇所 | `litellm/proxy/proxy_server.py`の128行目に12行のコード挿入 | 同上 + `litellm_init.pth`ファイルの追加 |
| 発動条件 | `litellm.proxy.proxy_server`モジュールがimportされた時 | **Pythonインタプリタが起動するたび（importすら不要）** |
| 発動タイミング | LiteLLMのProxyモードを使用した時 | `python --version`を実行しただけでも発動。pipの実行やIDEの言語サーバー起動でも発動する |

v1.82.7の注入コードは、正規のコードブロック（`REALTIME_REQUEST_SCOPE_TEMPLATE`辞書と`showwarning`関数の間）に挿入されており、コードレビューで見落としやすい位置に配置されていた。

v1.82.8の`litellm_init.pth`ファイルは、Pythonの`site-packages`ディレクトリに配置される`.pth`ファイルで、`site.py`がインタプリタ起動時に自動的に処理する。1行のコードで`subprocess`をimportし、デタッチされたPythonプロセスを起動してBase64ペイロードをデコード・実行する。

### 4.2 Stage 1：認証情報の収集

ペイロードは以下の50以上のカテゴリの機密情報を探索・収集する：

- SSH秘密鍵・設定ファイル（`~/.ssh/`）
- `.env`ファイル（プロジェクト内の全階層を再帰検索）
- AWS認証情報（`~/.aws/credentials`、IMDSv2メタデータ、Secrets Manager内容、SSMパラメータ）
- GCP ADC（Application Default Credentials）
- Azureトークン
- Kubernetes設定（`~/.kube/config`）
- データベースパスワード
- gitクレデンシャル（`~/.gitconfig`、`.git-credentials`）
- Dockerレジストリ認証（`~/.docker/config.json`）
- Terraformステートファイル
- シェル履歴（`.bash_history`、`.zsh_history`等）
- 暗号資産ウォレット
- CI/CDシークレット（環境変数経由）

収集したデータはAES-256セッション鍵で暗号化し、そのセッション鍵をRSA-4096で暗号化するハイブリッド暗号方式を使用。暗号化後、`models.litellm[.]cloud`（攻撃者のC2サーバー、LiteLLM公式ドメインではない）にHTTP POSTで送信される。ファイル名ヘッダーは`X-Filename: tpcp.tar.gz`。

### 4.3 Stage 2：Kubernetes横展開

Kubernetesトークンが見つかった場合、以下のアクションを自動実行する：

1. 全Namespaceのシークレットを読み取り
2. `kube-system` Namespaceに特権Podを全ノードにデプロイ：
   - Pod名：`node-setup-*`
   - イメージ：`alpine:latest`
   - 設定：`hostNetwork: true`、`hostPID: true`、`privileged: true`
   - ホストファイルシステムをマウント
3. 各ノード上で認証情報収集を繰り返し、クラスター全体に侵害を拡大

### 4.4 Stage 3：永続化

systemdバックドアを以下のパスにインストール：

- バックドア本体：`~/.config/sysmon/sysmon.py`
- systemdユニット：`~/.config/systemd/user/sysmon.service`（「System Telemetry Service」として偽装）

5分の初期遅延後、50分間隔で`checkmarx[.]zone/raw`をポーリングするループに入る。各サイクルでC2からURLを取得し、ローカルの状態ファイル（`/tmp/.pg_state`）と比較。新しいURLであれば、バイナリを`/tmp/pglog`にダウンロードして実行する。

**キルスイッチ：** C2のレスポンスに「youtube.com」が含まれる場合は実行を中止する。これはサンドボックスや分析環境での検知を回避するための手法。

### 4.5 アンチフォレンジック手法

- Base64難読化によるペイロードの隠蔽
- `subprocess.Popen`によるバックグラウンド実行（フォアグラウンドプロセス監視の回避）
- `.pth`自動ロードの悪用（パッケージ削除後も永続化）
- systemdサービスを正規のテレメトリサービスとして偽装
- キルスイッチによるサンドボックス検知の回避
- Trivyの侵害から得たインフラと手法の再利用

### 4.6 なぜ従来の防御が効かなかったか

`litellm_init.pth`ファイルはwheelのRECORDファイルに正しく宣言され、ハッシュも一致していた。`pip install --require-hashes`でもパスしてしまう。正規の認証情報で公開されたため、ハッシュ不一致も不審なドメインもパッケージ名のタイポもない。インストール時に`.pth`ファイルの内容を検査するpipプラグインは、現在広く普及していない。

---

## 5. 公式Dockerイメージの安全性確認

### 5.1 結論

**`ghcr.io/berriai/litellm:main-latest`を含む公式LiteLLM Dockerイメージは、今回のサプライチェーン攻撃の影響を受けていない。**

LiteLLM公式インシデントレポートに以下の記載がある：

> 「LiteLLM AI Gateway/Proxyユーザー：公式LiteLLM Proxy Dockerイメージを使用していたお客様は影響を受けていません。このデプロイパスはrequirements.txtで依存関係をピン留めしており、侵害されたPyPIパッケージに依存していません。」

Blackswan Cybersecurityの脅威インテリジェンスレポートでも、以下が明確に記載されている：

> 「影響なし：公式LiteLLM Dockerイメージ（ghcr.io/berriai/litellm）、LiteLLM Cloud、GitHubソースからのインストール、バージョン1.82.6以下。」

### 5.2 Dockerイメージが安全だった理由

攻撃者はPyPI認証情報を使ってPyPIに直接パッケージをアップロードしたが、GitHubリポジトリのソースコードは一切改変していない。Dockerイメージのビルドプロセスは以下の経路を取る：

```
GitHub main ブランチ → requirements.txt（バージョンピン済み）→ ビルド
                        ※ PyPIの latest タグを動的に取得しない
```

一方、攻撃ルートは：

```
窃取したPyPI認証情報 → PyPIに直接アップロード
                        ※ GitHubリポジトリは未改変
```

この2つのパスが完全に分離されていたことが、Dockerイメージの安全性を担保した。

### 5.3 影響判定まとめ

| デプロイ方法 | 判定 | 理由 |
|-------------|------|------|
| `ghcr.io/berriai/litellm:main-latest` | **セーフ** | GitHubソースからビルド、依存関係ピン済み |
| `ghcr.io/berriai/litellm:<特定バージョンタグ>` | **セーフ** | 同上 |
| LiteLLM Cloud | **セーフ** | 公式発表で影響なしと確認 |
| GitHubソースからの直接インストール | **セーフ** | PyPIを経由しない |
| `pip install litellm`（バージョン未指定、感染ウィンドウ中） | **アウト** | PyPIからv1.82.7/1.82.8を取得した可能性 |
| `pip install litellm==1.82.6`以前 | **セーフ** | 侵害前のバージョン |
| 推移的依存としてlitellmを取得したフレームワーク（MCP、AI Agent等） | **要確認** | バージョン未指定で取得していた場合はリスクあり |

### 5.4 Dockerイメージ利用者でも確認すべきケース

Dockerイメージ自体は安全だが、以下のカスタマイズをしていた場合は確認が必要：

1. **Dockerfile内で`pip install litellm --upgrade`を追加していた場合** — ビルド時にPyPIから最新版を取得し、感染バージョンがインストールされた可能性がある
2. **コンテナ内で手動で`pip install`を実行していた場合** — 同上
3. **Docker外の開発環境でlitellmをpipインストールしていた場合** — その環境は要確認
4. **AIエージェントフレームワークやMCPサーバーがlitellmを推移的依存として取り込んでいた場合** — バージョン確認が必要

---

## 6. 感染確認手順

### Step 1：バージョン確認

```bash
pip show litellm | grep Version
# 1.82.7 または 1.82.8 → 即アウト
# 1.82.6 以前 → セーフ
```

### Step 2：.pthファイルの確認

```bash
# site-packages内
find $(python -c "import site; print(':'.join(site.getsitepackages()))") \
  -name "litellm_init.pth" 2>/dev/null

# uvキャッシュ内
find ~/.cache/uv -name "litellm_init.pth" 2>/dev/null

# pipキャッシュ内
find ~/.cache/pip -name "litellm_init.pth" 2>/dev/null
```

### Step 3：永続化バックドアの確認

```bash
# systemdバックドア
ls -la ~/.config/sysmon/sysmon.py 2>/dev/null
ls -la ~/.config/systemd/user/sysmon.service 2>/dev/null
systemctl --user status sysmon.service 2>/dev/null

# C2ポーリングの状態ファイル
ls -la /tmp/.pg_state 2>/dev/null
ls -la /tmp/pglog 2>/dev/null
```

### Step 4：Kubernetes環境の確認

```bash
kubectl get pods -n kube-system | grep 'node-setup'
kubectl get secrets -n kube-system --sort-by='.metadata.creationTimestamp'
```

### Step 5：ネットワーク通信の確認

```bash
# C2ドメインへの通信痕跡
grep -rE 'models\.litellm\.cloud|checkmarx\.zone|83\.142\.209\.11' \
  /var/log/ 2>/dev/null

# DNS解決ログ
grep -rE 'models\.litellm\.cloud|checkmarx\.zone' \
  /var/log/syslog /var/log/dns* 2>/dev/null
```

### IOC（Indicator of Compromise）一覧

| 種別 | 値 |
|------|-----|
| C2ドメイン（データ送信先） | `models.litellm[.]cloud` |
| C2ドメイン（ペイロード取得） | `checkmarx[.]zone` |
| C2 IP | `83.142.209.11` |
| 送信ファイル名ヘッダー | `X-Filename: tpcp.tar.gz` |
| バックドア本体 | `~/.config/sysmon/sysmon.py` |
| systemdユニット | `~/.config/systemd/user/sysmon.service` |
| ポーリング状態ファイル | `/tmp/.pg_state` |
| ダウンロードされるバイナリ | `/tmp/pglog` |
| .pthファイル | `litellm_init.pth`（site-packages内） |
| Kubernetes不審Pod | `node-setup-*`（kube-system namespace） |

---

## 7. 感染が確認された場合の対応

1. **ネットワークからの即時隔離**
2. **litellmの削除とキャッシュのパージ**
   ```bash
   pip uninstall litellm
   pip cache purge
   rm -rf ~/.cache/uv
   ```
3. **永続化メカニズムの除去**
   ```bash
   systemctl --user stop sysmon.service
   systemctl --user disable sysmon.service
   rm -rf ~/.config/sysmon/
   rm -f ~/.config/systemd/user/sysmon.service
   rm -f /tmp/.pg_state /tmp/pglog
   ```
4. **全認証情報のローテーション**（別のクリーンなマシンから実施）
   - SSH鍵、AWS/GCP/Azure認証情報、Kubernetesトークン
   - APIキー（.envファイル内の全値）、データベースパスワード
   - PyPIトークン、npm トークン、Dockerレジストリ認証
5. **Kubernetes環境の確認と修復**
   - `kube-system`内の`node-setup-*` Podを削除
   - クラスターシークレットの不正アクセスを監査
6. **マシンのクリーンインストールまたは感染前バックアップからの復元**

---

## 8. 今後の防御策

### 8.1 LiteLLM利用者向け

- Dockerイメージ（`ghcr.io/berriai/litellm`）での運用を推奨
- pipで直接インストールする場合はバージョンをピン留め：`litellm==1.83.0`（修正済みCI/CD v2パイプラインでリリース）
- `.pth`ファイルの定期監査をCI/CDと開発環境の両方に導入

### 8.2 一般的なPythonサプライチェーン対策

- Dependency Cooldownの導入（uv: `exclude-newer = "P3D"`）
- ハッシュ検証付きインストール（`pip install --require-hashes`）
- `--only-binary :all:`によるsetup.py実行の回避
- pip-auditによる定期的な脆弱性スキャン
- CI/CDでの`pip install`にはGitHubソースからの直接インストールまたはピン留め済みrequirements.txtを使用

---

## 9. 参考リンク

### 公式情報

- **LiteLLM公式インシデントレポート:** https://docs.litellm.ai/blog/security-update-march-2026
- **PyPI公式インシデントレポート:** https://blog.pypi.org/posts/2026-04-02-incident-report-litellm-telnyx-supply-chain-attack/
- **GitHub Security Advisory:** GHSA-fw8c-xr5c-95f9

### セキュリティベンダー分析

- **Trend Micro（詳細技術分析）:** https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html
- **Snyk（攻撃チェーン分析）:** https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/
- **Endor Labs（最初の発見報告）:** https://www.endorlabs.com/learn/teampcp-isnt-done
- **Datadog Security Labs:** https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
- **Elastic Security Labs（axios分析）:** https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all
- **Zscaler ThreatLabz:** https://www.zscaler.com/blogs/security-research/supply-chain-attacks-surge-march-2026
- **Kaspersky:** https://www.kaspersky.com/blog/critical-supply-chain-attack-trivy-litellm-checkmarx-teampcp/55510/
- **Sonatype:** https://www.sonatype.com/blog/compromised-litellm-pypi-package-delivers-multi-stage-credential-stealer

### 発見者・コミュニティ

- **FutureSearch（最初の発見）:** https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/
- **Phoenix Security:** https://phoenix.security/teampcp-litellm-supply-chain-compromise-pypi-credential-stealer-kubernetes/
- **Blackswan Cybersecurity:** https://blackswan-cybersecurity.com/threat-intelligence-report-litellm-supply-chain-attack-march-24-2026-march-26-2026/
- **SISA:** https://www.sisainfosec.com/blogs/litellm-supply-chain-compromise-when-your-ai-dependency-becomes-an-attack-vector/
- **SIG:** https://www.softwareimprovementgroup.com/blog/litellm-supply-chain-attack/

### 関連攻撃・広域分析

- **DreamFactory（12日間で5件の攻撃の統合分析）:** https://blog.dreamfactory.com/five-supply-chain-attacks-in-twelve-days-how-march-2026-broke-open-source-trust-and-what-comes-next
- **Semgrep（TeamPCPキャンペーン全体像）:** https://semgrep.dev/blog/2026/the-teampcp-credential-infostealer-chain-attack-reaches-pythons-litellm/
- **Arthur.ai（AI チーム向けガイダンス）:** https://www.arthur.ai/column/litellm-supply-chain-attack-pypi-compromise-2026
