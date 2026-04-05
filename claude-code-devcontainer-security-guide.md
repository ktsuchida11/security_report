# Claude Code DevContainer環境におけるサプライチェーン攻撃対策

**作成日:** 2026年4月5日  
**対象:** Claude Code勉強会参加者（ベテランフルスタックエンジニア向け）  
**前提環境:** Claude Code + DevContainer + iptables Firewall + LiteLLM Proxy + MCP Server  
**GitHub:** github.com/ktsuchida11/claude-dev-env

---

## 1. なぜClaude Code環境がサプライチェーン攻撃の標的になるか

Claude Codeは開発者のターミナルで動作するエージェント型AIツールであり、以下の理由からサプライチェーン攻撃のリスクが高い：

- **npm経由でインストール可能** — npmの依存チェーン全体のリスクを継承する
- **ファイルシステムへの広範なアクセス権限** — ソースコード、設定ファイル、認証情報を読み取れる
- **シェルコマンドの実行権限** — `npm install`をClaude Code自身が実行する可能性がある
- **APIキーの保持** — Anthropic APIキー、LLMプロバイダーのキーが環境内に存在する
- **MCP Serverとの連携** — 外部サービスへの認証情報がDevContainer内に存在する可能性がある

2026年3月のaxiosサプライチェーン攻撃とClaude Codeソースコード流出が同日に発生したことは、npmエコシステム全体への依存リスクを象徴している。

---

## 2. DevContainer + Sandbox + Firewall の防御モデル

Kojiさんの`claude-dev-env`リポジトリの設計思想「build for breach, not for perfection」に基づき、以下の3層防御モデルを前提とする。

```
┌─────────────────────────────────────────────┐
│  Host OS                                     │
│  ┌───────────────────────────────────────┐   │
│  │  DevContainer (Sandbox)               │   │
│  │  ┌─────────────────────────────────┐  │   │
│  │  │  Claude Code                    │  │   │
│  │  │  + LiteLLM Proxy               │  │   │
│  │  │  + MCP Servers                  │  │   │
│  │  │  + 開発対象プロジェクト          │  │   │
│  │  └─────────────────────────────────┘  │   │
│  │  iptables Firewall（アウトバウンド制御）│   │
│  └───────────────────────────────────────┘   │
│  ホストの ~/.ssh, ~/.aws はマウントしない     │
└─────────────────────────────────────────────┘
```

### 各層の防御効果

| 防御層 | 防ぐもの | 防げないもの |
|--------|---------|-------------|
| **Firewall（iptables）** | C2サーバーへの通信、未知ドメインへのデータ送信 | ホワイトリスト内ドメインを悪用した攻撃 |
| **Sandbox（DevContainer）** | ホストOSへのファイルアクセス、ホストのネットワーク設定変更 | DevContainer内の認証情報へのアクセス |
| **エフェメラル性（rebuild）** | 永続化（systemdバックドア等） | 一度実行された認証情報の窃取 |

---

## 3. iptables Firewallの推奨設定

### 3.1 ホワイトリスト方式のアウトバウンド制御

```bash
#!/bin/bash
# firewall-setup.sh — DevContainer起動時に実行

# デフォルトポリシー：アウトバウンドを全拒否
iptables -P OUTPUT DROP

# ループバック通信を許可
iptables -A OUTPUT -o lo -j ACCEPT

# 確立済みの接続を許可（レスポンスの受信）
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# DNS解決を許可（必須）
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# === 許可するドメイン/IP ===

# Anthropic API（Claude Code必須）
iptables -A OUTPUT -d api.anthropic.com -p tcp --dport 443 -j ACCEPT

# npm レジストリ（パッケージインストール時のみ）
iptables -A OUTPUT -d registry.npmjs.org -p tcp --dport 443 -j ACCEPT

# GitHub（ソースコード取得）
iptables -A OUTPUT -d github.com -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -d raw.githubusercontent.com -p tcp --dport 443 -j ACCEPT

# PyPI（Python パッケージ、LiteLLM等）
iptables -A OUTPUT -d pypi.org -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -d files.pythonhosted.org -p tcp --dport 443 -j ACCEPT

# LiteLLM Proxy（ローカル通信のみ、外部不要）
# → LiteLLMがDevContainer内で動作する場合、外部通信はLLMプロバイダーのAPIのみ

# LLMプロバイダーAPI（LiteLLM経由で使用するもの）
iptables -A OUTPUT -d api.openai.com -p tcp --dport 443 -j ACCEPT
# 他のプロバイダーも必要に応じて追加

# === 明示的に拒否するもの（ログ付き） ===
iptables -A OUTPUT -j LOG --log-prefix "BLOCKED_OUTBOUND: " --log-level 4
iptables -A OUTPUT -j DROP
```

### 3.2 Firewall設定とSandbox許可ドメインの同期

`claude-dev-env`のSandbox設定（`settings.json`のdeny/allowルール）とiptablesのホワイトリストを同期させる。

| ドメイン | iptables | Claude Code Sandbox | 用途 |
|----------|----------|-------------------|------|
| `api.anthropic.com` | ACCEPT | allow | Claude API |
| `registry.npmjs.org` | ACCEPT | allow | npmパッケージ |
| `pypi.org` | ACCEPT | allow | Pythonパッケージ |
| `github.com` | ACCEPT | allow | ソースコード |
| `api.openai.com` | ACCEPT | allow | LLMプロバイダー |
| `sfrclak[.]com` | **DROP** | deny | axios攻撃C2 |
| `checkmarx[.]zone` | **DROP** | deny | LiteLLM攻撃C2 |
| `models.litellm[.]cloud` | **DROP** | deny | LiteLLM攻撃C2 |
| その他すべて | **DROP** | deny | デフォルト拒否 |

### 3.3 攻撃シナリオ別のFirewall効果

| 攻撃 | C2通信先 | ポート | Firewall効果 |
|------|---------|--------|-------------|
| axios（2026/3/31） | `sfrclak[.]com` | 8000 | **ブロック**（ドメインもポートも未許可） |
| LiteLLM（2026/3/24） | `models.litellm[.]cloud` | 443 | **ブロック**（ドメイン未許可） |
| LiteLLM永続化 | `checkmarx[.]zone` | 443 | **ブロック**（ドメイン未許可） |
| 未知の将来の攻撃 | 不明 | 不明 | **ブロック**（ホワイトリスト方式のため） |

---

## 4. DevContainer内のnpm設定

### 4.1 .npmrc（DevContainer内に配置）

```ini
# /workspace/.npmrc
ignore-scripts=true
save-exact=true
min-release-age=7
audit=true
engine-strict=true
fund=false
```

### 4.2 Dockerfile / devcontainer.json での設定

```jsonc
// .devcontainer/devcontainer.json
{
  "name": "claude-dev-env",
  "build": {
    "dockerfile": "Dockerfile"
  },
  "postCreateCommand": "npm ci --ignore-scripts",
  "mounts": [
    // ❌ ホストの認証情報はマウントしない
    // "source=${localEnv:HOME}/.ssh,target=/root/.ssh,type=bind"
    // "source=${localEnv:HOME}/.aws,target=/root/.aws,type=bind"
  ],
  "containerEnv": {
    // APIキーは環境変数で注入（ファイルではなく）
    "ANTHROPIC_API_KEY": "${localEnv:ANTHROPIC_API_KEY}"
  },
  "features": {
    // 必要最小限のツールのみインストール
  }
}
```

### 4.3 CLAUDE.mdへの追記

`claude-dev-env`のCLAUDE.mdに、サプライチェーン攻撃対策のルールを追加する：

```markdown
## セキュリティルール

### npm操作
- `npm install` の実行前に、必ず `--ignore-scripts` オプションを使用すること
- 新しいパッケージの追加時は `npm install --save-exact` でバージョンを完全固定
- `package-lock.json` の変更は必ずdiffを確認してからコミット
- 未知のパッケージを追加する前に、npm registryでメンテナー情報とダウンロード数を確認

### 禁止事項
- `--dangerously-skip-permissions` フラグの使用禁止
- ホストの `~/.ssh` や `~/.aws` をDevContainerにマウントしない
- `curl | sh` パターンでのスクリプト実行禁止
- Firewall設定の変更禁止（iptablesルールの編集）

### 外部通信
- 許可ドメイン以外への通信が必要な場合は、明示的にユーザーに確認を求めること
- `package.json` の `postinstall` フックが含まれるパッケージは、内容を確認してから手動実行
```

---

## 5. LiteLLM Proxyの安全な運用

### 5.1 Dockerイメージの使用（推奨）

```yaml
# docker-compose.yml（DevContainer内でのLiteLLM運用）
services:
  litellm:
    image: ghcr.io/berriai/litellm:main-v1.83.0  # タグを固定
    ports:
      - "4000:4000"  # DevContainer内部のみ
    environment:
      - LITELLM_MASTER_KEY=${LITELLM_MASTER_KEY}
    volumes:
      - ./litellm-config.yaml:/app/config.yaml
    # ネットワークはLLMプロバイダーAPIへのアクセスのみ許可
```

`ghcr.io/berriai/litellm:main-latest`はタグが可変のため、本番運用ではバージョンタグを固定する。

### 5.2 PyPIからのインストールは避ける

LiteLLMのPyPI配布物は2026年3月に侵害された実績があるため、Dockerイメージまたはソースコードからの直接インストールを推奨する。pipでインストールする場合は必ずバージョンをピン留めし、ハッシュ検証を併用する。

### 5.3 .pthファイルの監査

LiteLLMを含む環境では、定期的に`.pth`ファイルを監査するスクリプトをHooksに追加する：

```bash
#!/bin/bash
# hooks/check-pth-files.sh
echo "Checking for suspicious .pth files..."
SUSPICIOUS=$(find $(python3 -c "import site; print(':'.join(site.getsitepackages()))" 2>/dev/null) \
  -name "*.pth" -exec grep -l -E 'subprocess|exec|base64|import os' {} \; 2>/dev/null)

if [ -n "$SUSPICIOUS" ]; then
  echo "⚠️  WARNING: Suspicious .pth files found:"
  echo "$SUSPICIOUS"
  exit 1
fi
echo "✅ No suspicious .pth files found."
```

---

## 6. Hooks（Claude Code）でのセキュリティ強化

`claude-dev-env`のHooks機能を活用し、サプライチェーン攻撃の予防・検知を自動化する。

### 6.1 block-dangerous.sh の拡張

既存の`block-dangerous.sh`に、サプライチェーン攻撃関連のチェックを追加する：

```bash
#!/bin/bash
# hooks/block-dangerous.sh（拡張版）

COMMAND="$1"

# 既存のブロックルール（省略）
# ...

# === サプライチェーン攻撃対策 ===

# npm install を --ignore-scripts なしで実行しようとした場合に警告
if echo "$COMMAND" | grep -qE '^npm install' && ! echo "$COMMAND" | grep -q '\-\-ignore-scripts'; then
  echo "⚠️  BLOCKED: npm install without --ignore-scripts"
  echo "Use: npm ci --ignore-scripts"
  exit 1
fi

# pip install を検証なしで実行しようとした場合に警告
if echo "$COMMAND" | grep -qE '^pip install' && ! echo "$COMMAND" | grep -q '\-\-require-hashes\|\-\-only-binary'; then
  echo "⚠️  WARNING: pip install without --require-hashes or --only-binary"
  echo "Consider: pip install --only-binary :all: -r requirements.txt"
fi

# curl | sh パターンのブロック
if echo "$COMMAND" | grep -qE 'curl.*\|.*sh|wget.*\|.*sh'; then
  echo "⚠️  BLOCKED: pipe to shell execution"
  exit 1
fi
```

### 6.2 postinstall-audit.sh（新規）

```bash
#!/bin/bash
# hooks/postinstall-audit.sh
# npm ci 実行後に自動実行し、不審なパッケージを検出する

echo "=== Postinstall Security Audit ==="

# postinstallフックを持つパッケージを検出
echo "📦 Packages with postinstall hooks:"
find node_modules -maxdepth 2 -name "package.json" -exec \
  grep -l '"postinstall"' {} \; 2>/dev/null | head -20

# 既知の悪意あるパッケージ名を検索
echo ""
echo "🔍 Checking for known malicious packages:"
MALICIOUS_PACKAGES="plain-crypto-js @shadanai/openclaw @qqbrowser/openclaw-qbot"
for pkg in $MALICIOUS_PACKAGES; do
  if [ -d "node_modules/$pkg" ]; then
    echo "  🚨 CRITICAL: Found $pkg in node_modules!"
  fi
done

# .pthファイルの検査（Python環境がある場合）
if command -v python3 &>/dev/null; then
  echo ""
  echo "🐍 Checking Python .pth files:"
  find $(python3 -c "import site; print(':'.join(site.getsitepackages()))" 2>/dev/null) \
    -name "*.pth" -exec sh -c 'echo "  $1"; grep -c "subprocess\|exec\|base64" "$1" | \
    xargs -I{} test {} -gt 0 && echo "    ⚠️  Contains suspicious patterns"' _ {} \; 2>/dev/null
fi

echo ""
echo "✅ Audit complete."
```

---

## 7. 勉強会でのデモシナリオ

Claude Code勉強会（2セッション構成）のAppliedセッションで、以下のデモを提案する。

### デモ1：攻撃の再現（安全な環境で）

```bash
# DevContainer内で、Firewall有効な状態で擬似的なpostinstallフックを実行
# → iptablesがアウトバウンド通信をブロックする様子を確認

# 1. テスト用のpostinstallスクリプトを作成
cat > /tmp/test-postinstall.js << 'EOF'
const http = require('http');
const req = http.request('http://example.com:8000/test', (res) => {
  console.log('Response:', res.statusCode);
});
req.on('error', (e) => {
  console.log('Blocked by firewall:', e.message);
});
req.end();
EOF

# 2. 実行 → Firewallでブロックされることを確認
node /tmp/test-postinstall.js
# → "Blocked by firewall: connect ETIMEDOUT ..." が表示される
```

### デモ2：防御設定の確認

```bash
# .npmrc の設定確認
npm config list

# min-release-ageの動作確認
npm install some-package --min-release-age=9999
# → 最近公開されたバージョンがスキップされることを確認

# ignore-scriptsの動作確認
npm ci --ignore-scripts
# → postinstallが実行されないことを確認
```

### デモ3：IOC検索の実演

```bash
# axios攻撃のIOC検索
grep -r 'plain-crypto-js' node_modules/ 2>/dev/null
find / -name "ld.py" -path "/tmp/*" 2>/dev/null

# LiteLLM攻撃のIOC検索
find / -name "litellm_init.pth" 2>/dev/null
ls -la ~/.config/sysmon/ 2>/dev/null
```

---

## 8. まとめ：DevContainer環境のセキュリティチェックリスト

| # | 項目 | 設定場所 | 状態 |
|---|------|---------|------|
| 1 | iptablesホワイトリスト方式 | firewall-setup.sh | ☐ |
| 2 | `.npmrc`に`ignore-scripts=true` | .npmrc | ☐ |
| 3 | `.npmrc`に`min-release-age=7` | .npmrc | ☐ |
| 4 | `.npmrc`に`save-exact=true` | .npmrc | ☐ |
| 5 | CI/CDで`npm ci`を使用 | CI設定 | ☐ |
| 6 | `package-lock.json`をコミット | .gitignore確認 | ☐ |
| 7 | ホストの認証情報をマウントしない | devcontainer.json | ☐ |
| 8 | LiteLLMはDockerイメージで運用 | docker-compose.yml | ☐ |
| 9 | CLAUDE.mdにセキュリティルール追加 | CLAUDE.md | ☐ |
| 10 | Hooksにblock-dangerous.sh設置 | hooks/ | ☐ |
| 11 | .pthファイル監査スクリプト設置 | hooks/ | ☐ |
| 12 | Sandbox deny/allowルールとFW同期 | settings.json + FW | ☐ |

---

## 9. 参考リンク

### Claude Code DevContainer関連

- Claude Code公式セキュリティドキュメント: https://code.claude.com/docs/en/setup
- claude-dev-env リポジトリ: https://github.com/ktsuchida11/claude-dev-env

### npm対策

- npm `min-release-age`: https://docs.npmjs.com/cli/v11/using-npm/config#min-release-age
- Socket.dev「npm Introduces minimumReleaseAge」: https://socket.dev/blog/npm-introduces-minimumreleaseage-and-bulk-oidc-configuration
- ArmorCode「Defending Against NPM Supply Chain Attacks」: https://www.armorcode.com/blog/defending-against-npm-supply-chain-attacks-a-practical-guide

### 攻撃分析

- Elastic Security Labs（axios）: https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all
- Trend Micro（LiteLLM/TeamPCP）: https://www.trendmicro.com/en_us/research/26/c/inside-litellm-supply-chain-compromise.html
- Snyk（LiteLLM）: https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/
- LiteLLM公式インシデントレポート: https://docs.litellm.ai/blog/security-update-march-2026
- DreamFactory（12日間5件の統合分析）: https://blog.dreamfactory.com/five-supply-chain-attacks-in-twelve-days-how-march-2026-broke-open-source-trust-and-what-comes-next

### Python対策

- PyPI公式「Dependency Cooldowns」: https://blog.pypi.org/posts/2026-04-02-incident-report-litellm-telnyx-supply-chain-attack/
- Bernát Gábor「Defense in Depth: Python Supply Chain Security」: https://bernat.tech/posts/securing-python-supply-chain/
