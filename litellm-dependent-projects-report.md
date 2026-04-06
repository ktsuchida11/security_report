# LiteLLMに依存する生成AI関連プロジェクト一覧

**作成日:** 2026年4月6日  
**目的:** LiteLLMサプライチェーン攻撃（2026年3月24日）の推移的依存関係による影響範囲の特定  
**出典:** 各プロジェクトのGitHub Issue/PR、セキュリティベンダー分析、LiteLLM公式ドキュメント

---

## 1. 要約

LiteLLMは月間9,500万ダウンロード、クラウド環境の36%に存在する（Wiz調査）。多くのAI/MLフレームワークがLiteLLMをバージョン未固定（`litellm>=1.64.0`のように下限のみ指定）で推移的依存に含んでいる。

そのため、`pip install crewai`や`pip install dspy`を実行するだけで、感染ウィンドウ中にはlitellm v1.82.7/v1.82.8がインストールされ得た。直接litellmを使っていないプロジェクトでも影響を受ける可能性がある。

---

## 2. 攻撃当日にセキュリティPR/Issueを発行した下流プロジェクト（影響確認済み）

以下のプロジェクトは、攻撃当日（3月24日）にlitellmのバージョンピン留めPRまたはセキュリティIssueを発行しており、推移的依存としてlitellmを含んでいたことが確認されている。

| プロジェクト | GitHub Stars | 種別 | 対応 | ソース |
|------------|-------------|------|------|--------|
| **DSPy** (Stanford NLP) | 25k+ | LLMプログラミングフレームワーク | `litellm>=1.64.0,<=1.82.6`にピン留め | [stanfordnlp/dspy#9500](https://github.com/stanfordnlp/dspy/issues/9500) |
| **MLflow** | 20k+ | MLライフサイクル管理 | `litellm<=1.82.6`にピン留め | [mlflow/mlflow#21971](https://github.com/mlflow/mlflow/pull/21971) |
| **CrewAI** | 30k+ | マルチエージェントオーケストレーション | セキュリティPR発行 | Trend Micro分析 |
| **OpenHands** (旧OpenDevin) | 50k+ | AIソフトウェアエンジニアエージェント | セキュリティPR発行 | Trend Micro分析 |
| **Arize Phoenix** | 10k+ | LLMオブザーバビリティ | セキュリティPR発行 | Trend Micro分析 |
| **Google ADK** (Agent Development Kit) | 15k+ | GoogleのAIエージェント開発キット | `[eval]`/`[extensions]`エクストラで依存 | [google/adk-python#4986](https://github.com/google/adk-python/issues/4986) |

### DSPyに関する重要な注記

DSPyのメンテナーは以下のように述べている：

> 「`pip install dspy`や`uv pip install dspy`を実行した場合、uv.lockのバージョン制約を尊重しないため、システムが侵害された可能性が高い。」「今後のメジャーリリースで、LiteLLMへの依存を削除する可能性がかなり高い。」

### Google ADKに関する重要な注記

Google ADKは`[eval]`および`[extensions]`エクストラでlitellmを依存として含む。LiteLLMのPyPI隔離により、`pip install google-adk[eval]`自体がインストール不能になるという副次的影響も発生した。

---

## 3. LiteLLM公式ドキュメントに掲載されている連携プロジェクト

LiteLLM公式の「Projects built on LiteLLM」ページおよびREADMEに記載されているプロジェクト。これらはLiteLLMをSDKまたはProxy経由で使用しており、推移的依存として含む場合と、Proxy（Docker）経由で外部利用する場合がある。

### AIエージェントフレームワーク

| プロジェクト | 説明 | 依存形態 |
|------------|------|---------|
| **CrewAI** | マルチエージェントオーケストレーション | PyPI依存 |
| **OpenHands** | AIソフトウェアエンジニア | PyPI依存 |
| **Camel-AI** | LLMマルチエージェント通信 | PyPI依存 |
| **Agno** | エージェントフレームワーク | PyPI依存 |
| **Nanobot** | 軽量エージェント | PyPI依存 |
| **mini-swe-agent** | GitHubイシュー自動解決 | Proxy連携 |
| **Harbor** | エージェント評価・最適化 | Proxy連携 |
| **Railtracks** | レジリエントなエージェントシステム | PyPI依存 |

### ML/AIフレームワーク・ツール

| プロジェクト | 説明 | 依存形態 |
|------------|------|---------|
| **DSPy** (Stanford) | LLMプログラミングフレームワーク | PyPI依存（`litellm>=1.64.0`） |
| **MLflow** | MLライフサイクル管理 | PyPI依存 |
| **Instructor** | 構造化LLM出力（Pydantic統合） | PyPI依存 |
| **Guardrails AI** | LLMバリデーション | PyPI依存 |
| **Mem0** | AI記憶レイヤー | PyPI依存 |
| **Browser-Use** | AIブラウザ自動操作 | PyPI依存 |
| **GraphRAG** (Microsoft) | RAGパイプライン | Proxy連携 |
| **Otter** | マルチモーダルモデル（OpenFlamingo） | PyPI依存 |
| **YiVal** | GenAI-Opsフレームワーク | PyPI依存 |

### クラウド/エンタープライズ連携

| プロジェクト | 説明 | 依存形態 |
|------------|------|---------|
| **Google ADK** | GoogleのAIエージェント開発キット | PyPI依存（`[eval]`/`[extensions]`） |
| **Microsoft Agent Lightning** | RL/プロンプト最適化 | Proxy連携 |
| **Vertex AI Agent Engine** | Google Cloud AIエージェント | Proxy連携 |
| **Azure AI Foundry** | Microsoft Azure AI | Proxy連携 |
| **AWS Bedrock AgentCore** | Amazon Bedrock | Proxy連携 |
| **Pydantic AI** | Pydantic統合LLMフレームワーク | Proxy連携 |
| **LangGraph** | LangChainのグラフベースエージェント | Proxy連携 |

### モニタリング・オブザーバビリティ

| プロジェクト | 説明 | 依存形態 |
|------------|------|---------|
| **Opik** (Comet) | LLMモニタリング・評価 | PyPI依存 |
| **Arize Phoenix** | LLMオブザーバビリティ | PyPI依存 |
| **HolmesGPT** | AI運用監視 | PyPI依存 |
| **LangFuse** | LLMオブザーバビリティ | Proxy連携（間接） |

### ナレッジ管理・その他

| プロジェクト | 説明 | 依存形態 |
|------------|------|---------|
| **Quivr** | AIセカンドブレイン | PyPI依存 |
| **llmcord.py** | DiscordでのLLMチャット | PyPI依存 |

---

## 4. Mercor（確認済み被害企業）

AI人材採用スタートアップのMercorは、LiteLLMサプライチェーン攻撃の下流被害企業として公式に確認されている。窃取された認証情報が悪用され、ソースコードを含む大規模なデータ流出が発生したと報じられている。

---

## 5. 依存形態別のリスク評価

| 依存形態 | リスク | 説明 |
|---------|--------|------|
| **PyPI直接依存**（`pip install litellm`） | **高** | 感染ウィンドウ中にインストールしたらアウト |
| **PyPI推移的依存**（`pip install crewai`→litellm） | **高** | バージョン未固定なら同上 |
| **Proxy連携**（Docker `ghcr.io/berriai/litellm`） | **セーフ** | DockerイメージはPyPIから取得しない |
| **Proxy連携**（`pip install litellm[proxy]`） | **高** | PyPI経由ならリスクあり |
| **API連携のみ**（LiteLLM Proxy ServerにHTTPリクエスト） | **セーフ** | クライアント側にlitellmは不要 |

---

## 6. 確認コマンド

### 自分の環境にlitellmが推移的に入っているか確認

```bash
# litellmの存在確認
pip show litellm 2>/dev/null

# 何がlitellmを引き込んでいるか確認
pip show litellm 2>/dev/null | grep "Required-by"

# 依存ツリーでlitellmを検索
pip install pipdeptree
pipdeptree --reverse --packages litellm

# 全仮想環境を一括検索
find ~/ -type d -name "litellm-*.dist-info" 2>/dev/null | while read dir; do
  version=$(grep -m1 "^Version:" "$dir/METADATA" 2>/dev/null | awk '{print $2}')
  venv=$(echo "$dir" | sed 's|/lib/python.*/site-packages/.*||')
  if [ "$version" = "1.82.7" ] || [ "$version" = "1.82.8" ]; then
    echo "🚨 COMPROMISED: $version in $venv"
  else
    echo "✅ OK: $version in $venv"
  fi
done
```

### よくあるパターン

```bash
# これらのインストールでlitellmが推移的に入る可能性がある
pip install crewai        # → litellm
pip install dspy          # → litellm
pip install mlflow        # → litellm（MLflow Gatewayモジュール）
pip install browser-use   # → litellm
pip install google-adk[eval]      # → litellm
pip install google-adk[extensions] # → litellm
pip install instructor    # → litellm（オプション）
pip install guardrails-ai # → litellm（オプション）
pip install mem0ai        # → litellm
pip install opik          # → litellm
pip install quivr         # → litellm
pip install agno          # → litellm
pip install camel-ai      # → litellm
```

---

## 7. LangChain / LangGraph / LangFuse について

Kojiさんが使用しているLangChain、LangGraph、LangFuseについて：

| ツール | litellmへの直接依存 | 推移的依存の可能性 | 備考 |
|--------|-------------------|------------------|------|
| **LangChain** | **なし** | 低 | 独自のプロバイダー抽象化を持つ |
| **LangGraph** | **なし** | 低 | LangChain上に構築 |
| **LangFuse** | **なし** | 低 | オブザーバビリティツール、litellmとはProxy経由で連携 |

LangChain/LangGraph/LangFuse自体はlitellmに依存していません。ただし、これらと併用して他のAIツール（CrewAI、DSPy、Instructor等）をインストールしている場合は、そちら経由でlitellmが入っている可能性があります。

---

## 8. 600+プロジェクトの全体像

DreamFactoryの分析によると、600以上の公開GitHubプロジェクトがLiteLLMをバージョン未固定で依存に含んでおり、感染ウィンドウ中にCI/CDパイプラインで`pip install`が実行されていた場合は影響を受けた可能性がある。

StepSecurityは以下のように指摘している：

> 「LiteLLMは多数のAIフレームワークやツールの推移的依存です。ほとんどのプロジェクトが`litellm>=`で上限なしにピン留めしているため、直接litellmに依存していないユーザーでもv1.82.7やv1.82.8を取得した可能性があります。」

---

## 9. 代替手段

LiteLLM攻撃後、いくつかのプロジェクトはlitellmへの依存を見直す動きを見せている。

| 代替手段 | 特徴 |
|---------|------|
| **直接プロバイダーSDK**（openai、anthropic等） | 依存チェーンが浅い。最もセキュア |
| **Bifrost** | Go実装、OSSのLLMゲートウェイ。P99レイテンシが54倍高速 |
| **Portkey** | 商用AIゲートウェイ |
| **TensorZero** | Rust実装、サブミリ秒オーバーヘッド |
| **Cloudflare AI Gateway** | マネージドエッジサービス |
| **litelm**（新規） | litellmの軽量代替。2,300行、依存2つ（openai、httpx）。DSPyドロップイン対応 |

DSPyのメンテナーは「今後のメジャーリリースでlitellmへの依存を削除し、直接プロバイダーSDKへの移行を検討する」と表明している。

---

## 10. 参考リンク

### 各プロジェクトのセキュリティ対応

- DSPy: https://github.com/stanfordnlp/dspy/issues/9500
- MLflow: https://github.com/mlflow/mlflow/pull/21971
- Google ADK: https://github.com/google/adk-python/issues/4986
- Google ADK（隔離影響）: https://github.com/google/adk-python/issues/4981

### 分析記事

- Comet/Opik（影響範囲分析）: https://www.comet.com/site/blog/litellm-supply-chain-attack/
- DreamFactory（600+プロジェクト分析）: https://blog.dreamfactory.com/the-litellm-supply-chain-attack-a-complete-technical-breakdown-of-what-happened-who-is-affected-and-what-comes-next
- Cybernews（下流影響）: https://cybernews.com/security/critical-litellm-supply-chain-attack-sends-shockwaves/
- Snyk（AI blast radius分析）: https://snyk.io/blog/litellm-ai-blast-radius/
- Trend Micro（下流PR一覧）: https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html
- Wiz（36%クラウド環境）: https://www.wiz.io/blog/threes-a-crowd-teampcp-trojanizes-litellm-in-continuation-of-campaign
- paddo.dev（推移的依存リスク）: https://paddo.dev/blog/litellm-supply-chain-attack-dependency-trap/

### LiteLLM公式

- 公式プロジェクト一覧: https://docs.litellm.ai/docs/project
- インシデントレポート: https://docs.litellm.ai/blog/security-update-march-2026
