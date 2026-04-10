# .env ファイル暗号化 & 多層防御ガイド

## はじめに — 「暗号化だけ」では足りない理由

`.env` を暗号化しても、秘密鍵（`.env.keys` や age の秘密鍵）が同じマシン上の
平文ファイルに置いてあれば、サプライチェーン攻撃等でプロセスに侵入された時点で
秘密鍵ごと読み取られる。

**暗号化は「Gitリポジトリ経由の漏洩」を防ぐレイヤーであり、ランタイムの防御ではない。**

本ガイドでは以下の **4層の防御** を組み合わせる：

| 層 | 守るもの | 手段 |
|----|---------|------|
| **Layer 1: 暗号化** | リポジトリ・転送経路 | dotenvx / SOPS |
| **Layer 2: 鍵の隔離** | 秘密鍵をファイルシステムから排除 | OS Keychain / Secrets Manager / 環境変数注入 |
| **Layer 3: アクセス制御** | ファイル・プロセスへの不正アクセス | ファイル権限 / MAC / プロセス分離 |
| **Layer 4: 検知・監視** | 侵害の早期発見 | ファイル改竄検知 / 監査ログ / 異常検知 |

---

## 目次

1. [Layer 1: 暗号化 — dotenvx と SOPS](#layer-1-暗号化)
2. [Layer 2: 鍵の隔離 — 秘密鍵をファイルに置かない](#layer-2-鍵の隔離)
3. [Layer 3: アクセス制御 — OS レベルの防御](#layer-3-アクセス制御)
4. [Layer 4: 検知・監視](#layer-4-検知監視)
5. [Python 実装例（多層防御統合）](#python-実装例)
6. [脅威シナリオ別の防御マッピング](#脅威シナリオ別の防御マッピング)
7. [クイックリファレンス](#クイックリファレンス)

---

## Layer 1: 暗号化

### dotenvx

```bash
# インストール（Mac / Linux / Windows 共通）
npm install @dotenvx/dotenvx -g
# Mac/Linux: brew install dotenvx/brew/dotenvx

# 暗号化
dotenvx encrypt

# 復号して起動
dotenvx run -- python app.py
```

生成ファイル:

| ファイル | 内容 | Git |
|---------|------|-----|
| `.env` | 暗号化済みの値 + 公開鍵 | ✅ コミットOK |
| `.env.keys` | 復号用秘密鍵 | ❌ **コミット厳禁** |

**⚠️ dotenvx の限界**: `.env.keys` がローカルファイルとして存在する。
→ Layer 2 で鍵をファイルシステムから排除する。

### SOPS + age

```bash
# Mac
brew install sops age

# Linux
sudo apt install age
# sops は GitHub Releases からバイナリ取得

# Windows
scoop install sops age
```

```bash
# age 鍵生成
age-keygen -o key.txt

# 暗号化（キー名は平文、値だけ暗号化）
sops --encrypt --input-type dotenv --output-type dotenv .env > .env.enc

# 復号
sops --decrypt --input-type dotenv --output-type dotenv .env.enc > .env

# エディタで直接編集（復号→編集→保存時に再暗号化）
sops --input-type dotenv --output-type dotenv .env.enc
```

`.sops.yaml`（プロジェクトルート）:

```yaml
creation_rules:
  # .env 用
  - path_regex: \.env\.enc$
    age: >-
      age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

  # Terraform secrets と鍵を統一
  - path_regex: \.tfvars\.json$
    age: >-
      age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

  # AWS KMS 併用（チーム運用）
  # - path_regex: \.env\.enc$
  #   kms: arn:aws:kms:ap-northeast-1:123456789:key/xxxxxxxx
```

**⚠️ SOPS + age の限界**: `~/.config/sops/age/keys.txt` がローカルファイル。
→ 同様に Layer 2 で対策する。

---

## Layer 2: 鍵の隔離

**目的: 秘密鍵をファイルシステム上の平文から排除する**

### 方式1: OS Keychain / Credential Store に格納

秘密鍵をファイルではなく OS のセキュアストレージに保存する。
プロセスが鍵にアクセスするには OS の認証（Touch ID / パスワード）が必要になる。

#### Mac — Keychain Access

```bash
# 秘密鍵を Keychain に格納
security add-generic-password \
  -a "$USER" \
  -s "dotenvx-private-key" \
  -w "$(cat .env.keys | grep DOTENV_PRIVATE_KEY | cut -d'=' -f2)" \
  -T "" \
  -U

# 取り出し（Touch ID / パスワード認証が発生）
security find-generic-password \
  -a "$USER" \
  -s "dotenvx-private-key" \
  -w

# age 秘密鍵も同様に格納可能
security add-generic-password \
  -a "$USER" \
  -s "sops-age-key" \
  -w "$(grep 'AGE-SECRET-KEY' ~/.config/sops/age/keys.txt)" \
  -T "" \
  -U
```

```bash
# 格納後、ファイルを安全に削除
rm -P .env.keys                         # Mac: -P で上書き削除
shred -u ~/.config/sops/age/keys.txt    # Linux: shred で完全削除
```

利用時のラッパースクリプト（`run-with-secrets.sh`）:

```bash
#!/bin/bash
# Mac Keychain から秘密鍵を取得して環境変数として渡す
export DOTENV_PRIVATE_KEY=$(
  security find-generic-password -a "$USER" -s "dotenvx-private-key" -w
)
dotenvx run -- "$@"
```

#### Linux — GNOME Keyring / libsecret

```bash
# secret-tool（libsecret CLI）で格納
cat .env.keys | grep DOTENV_PRIVATE_KEY | cut -d'=' -f2 | \
  secret-tool store --label="dotenvx key" service dotenvx account private-key

# 取り出し
secret-tool lookup service dotenvx account private-key
```

```bash
# ファイルを安全に削除
shred -u .env.keys
```

#### Windows — Credential Manager / DPAPI

```powershell
# PowerShell: Credential Manager に格納
$key = Get-Content .env.keys | Select-String "DOTENV_PRIVATE_KEY" |
       ForEach-Object { $_.ToString().Split("=",2)[1] }
cmdkey /generic:"dotenvx-private-key" /user:"$env:USERNAME" /pass:"$key"

# DPAPI で暗号化してファイル保存（ユーザーセッションに紐づく）
$bytes = [System.Text.Encoding]::UTF8.GetBytes($key)
$encrypted = [System.Security.Cryptography.ProtectedData]::Protect(
  $bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser
)
[System.IO.File]::WriteAllBytes("$env:APPDATA\sops-age-key.dpapi", $encrypted)
```

```powershell
# 元ファイルを削除
Remove-Item .env.keys -Force
# より安全にするには cipher /w で空き領域を上書き
```

### 方式2: AWS Secrets Manager / SSM Parameter Store（本番環境推奨）

秘密鍵そのものをクラウドのシークレットマネージャに格納。
IAM ロールで認可するため、ファイルも環境変数も不要。

```bash
# age 秘密鍵を Secrets Manager に格納
aws secretsmanager create-secret \
  --name "myapp/sops-age-key" \
  --secret-string "$(grep 'AGE-SECRET-KEY' keys.txt)"

# 値を取得
aws secretsmanager get-secret-value \
  --secret-id "myapp/sops-age-key" \
  --query SecretString --output text
```

**SOPS + AWS KMS なら鍵ファイル自体が不要**:
KMS キーを使えば age 秘密鍵すら持つ必要がない。
IAM ロールが KMS の Decrypt 権限を持っていれば SOPS が直接復号する。

```yaml
# .sops.yaml — KMS のみ（age 鍵不要）
creation_rules:
  - path_regex: \.env\.enc$
    kms: arn:aws:kms:ap-northeast-1:123456789:key/your-key-id
```

```bash
# EC2 / ECS / Lambda で実行（IAMロールで自動認証、鍵ファイル不要）
sops --decrypt --input-type dotenv --output-type dotenv .env.enc > /dev/stdout
```

### 方式3: シークレット自体をクラウドに置く（最も安全）

「.env ファイルを暗号化する」のではなく、**そもそも .env を使わない** 選択肢。
シークレット値をクラウドのシークレットマネージャに直接格納し、
アプリが実行時に API で取得する。

```bash
# 各シークレットを Secrets Manager に登録
aws secretsmanager create-secret \
  --name "myapp/database-url" \
  --secret-string "postgresql://user:pass@host/db"

aws secretsmanager create-secret \
  --name "myapp/api-key" \
  --secret-string "sk-secret-12345"
```

→ Python 実装例は後述

### 方式の比較

| 方式 | セキュリティ | 利便性 | コスト | 適用場面 |
|------|------------|--------|--------|---------|
| OS Keychain | ★★★ | ★★★ | 無料 | ローカル開発 |
| Secrets Manager | ★★★★ | ★★★ | 低額 | ステージング / 本番 |
| KMS + SOPS（鍵ファイル不要） | ★★★★ | ★★★★ | 低額 | 本番（Terraform統一運用） |
| Secrets Manager 直接取得 | ★★★★★ | ★★ | 低額 | 本番（.env 完全廃止） |

---

## Layer 3: アクセス制御

### ファイル権限（全 OS 共通の基本）

```bash
# .env 関連ファイルは所有者のみ読み書き
chmod 600 .env .env.keys .env.enc
chmod 700 ~/.config/sops/age/

# Linux: 所有者を確認
ls -la .env*
# -rw------- 1 koji koji  .env
# -rw------- 1 koji koji  .env.keys
```

### Mac — App Sandbox / TCC

macOS の Transparency, Consent, and Control (TCC) が
アプリごとのファイルアクセスを制御している。
LuLu でネットワーク、Bitdefender でマルウェアをカバーしているなら、
さらに以下を確認:

```bash
# フルディスクアクセスを持つアプリを確認
# システム設定 → プライバシーとセキュリティ → フルディスクアクセス
# → 不要なアプリを無効化

# ターミナルのフルディスクアクセスも必要最小限に
```

### Linux — Mandatory Access Control (MAC)

```bash
# AppArmor（Ubuntu）: プロファイルでアプリのファイルアクセスを制限
# /etc/apparmor.d/myapp
/usr/bin/python3 {
  # .env は読み取り許可
  /opt/myapp/.env r,
  /opt/myapp/.env.enc r,

  # age 秘密鍵ディレクトリはアクセス拒否
  deny /home/*/.config/sops/** rw,

  # ネットワーク: 必要なポートのみ
  network tcp,
}
```

### プロセス分離 — シークレットを親プロセスの環境変数に残さない

```python
import os
import subprocess

def run_with_secrets(cmd: list[str], env_file: str = ".env.enc"):
    """シークレットを子プロセスだけに渡し、親の environ を汚染しない"""
    result = subprocess.run(
        ["sops", "--decrypt", "--input-type", "dotenv",
         "--output-type", "dotenv", env_file],
        capture_output=True, text=True, check=True,
    )

    # 親プロセスの環境変数をコピーし、復号した値を追加
    child_env = os.environ.copy()
    for line in result.stdout.strip().splitlines():
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            child_env[key.strip()] = value.strip().strip('"')

    # 子プロセスにのみ渡す（親の os.environ には入らない）
    subprocess.run(cmd, env=child_env, check=True)
```

### /proc 経由の環境変数漏洩を防ぐ（Linux）

Linux では `/proc/<pid>/environ` から他プロセスの環境変数を読める場合がある:

```bash
# hidepid=2 で他ユーザーのプロセス情報を隠す
sudo mount -o remount,hidepid=2 /proc

# 永続化: /etc/fstab に追記
# proc /proc proc defaults,hidepid=2 0 0
```

---

## Layer 4: 検知・監視

### ファイル改竄検知

```bash
# .env 関連ファイルのハッシュを記録
sha256sum .env .env.enc > .env.checksums

# CI/CD やデプロイ時に検証
sha256sum -c .env.checksums
```

### Git pre-commit フック — 平文の .env コミット防止

```bash
#!/bin/bash
# .git/hooks/pre-commit（または pre-commit framework で管理）

# 平文の .env がステージされていないか確認
STAGED=$(git diff --cached --name-only)

for f in $STAGED; do
  if [[ "$f" =~ ^\.env(\..+)?$ ]] && [[ ! "$f" =~ \.enc$ ]]; then
    # 暗号化されているか確認
    if ! head -1 "$f" | grep -q "DOTENV_PUBLIC_KEY\|sops_"; then
      echo "ERROR: 平文の $f がコミットされようとしています"
      echo "  dotenvx encrypt または sops --encrypt を実行してください"
      exit 1
    fi
  fi
done
```

### gitleaks — リポジトリ全体のシークレットスキャン

```bash
# インストール
brew install gitleaks  # Mac
# Linux: GitHub Releases からバイナリ取得

# リポジトリ全体をスキャン
gitleaks detect --source . --verbose

# pre-commit 連携
gitleaks protect --staged --verbose
```

### AWS CloudTrail — KMS / Secrets Manager の監査

KMS や Secrets Manager を使っている場合、誰がいつ復号したかを CloudTrail で追跡可能:

```bash
# Decrypt イベントを検索
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=Decrypt \
  --max-results 10
```

---

## Python 実装例

### パターン1: dotenvx + Keychain ラッパー（ローカル開発向け）

```python
# config_dotenvx.py
"""
dotenvx の秘密鍵を OS Keychain から取得して復号する。
.env.keys をファイルとして残さない運用。
"""
import os
import platform
import subprocess


def _get_key_from_keychain(service: str = "dotenvx-private-key") -> str:
    """OS の Keychain / Credential Store から秘密鍵を取得"""
    system = platform.system()

    if system == "Darwin":  # macOS
        return subprocess.run(
            ["security", "find-generic-password",
             "-a", os.environ["USER"], "-s", service, "-w"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()

    elif system == "Linux":
        return subprocess.run(
            ["secret-tool", "lookup", "service", "dotenvx", "account", "private-key"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()

    elif system == "Windows":
        # PowerShell 経由で Credential Manager から取得
        ps_cmd = (
            '(New-Object System.Net.NetworkCredential('
            '"", (Get-StoredCredential -Target "dotenvx-private-key").Password'
            ')).Password'
        )
        return subprocess.run(
            ["powershell", "-Command", ps_cmd],
            capture_output=True, text=True, check=True,
        ).stdout.strip()

    raise RuntimeError(f"Unsupported OS: {system}")


def load_dotenvx_secure():
    """Keychain から鍵を取得し、dotenvx で復号して環境変数にロード"""
    os.environ["DOTENV_PRIVATE_KEY"] = _get_key_from_keychain()

    result = subprocess.run(
        ["dotenvx", "get", "--format", "shell"],
        capture_output=True, text=True, check=True,
    )

    for line in result.stdout.strip().splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            os.environ[key] = value.strip("'\"")


if __name__ == "__main__":
    load_dotenvx_secure()
    print(f"DB: {os.environ.get('DATABASE_URL', 'NOT SET')}")
```

### パターン2: SOPS + age（Keychain連携 / ローカル開発）

```python
# config_sops.py
"""
SOPS + age の秘密鍵を OS Keychain から取得して復号。
~/.config/sops/age/keys.txt をファイルとして残さない運用。
"""
import os
import platform
import subprocess
import tempfile
from pathlib import Path
from contextlib import contextmanager


def _get_age_key_from_keychain() -> str:
    """OS Keychain から age 秘密鍵を取得"""
    system = platform.system()

    if system == "Darwin":
        return subprocess.run(
            ["security", "find-generic-password",
             "-a", os.environ["USER"], "-s", "sops-age-key", "-w"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()

    elif system == "Linux":
        return subprocess.run(
            ["secret-tool", "lookup", "service", "sops-age", "account", "secret-key"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()

    raise RuntimeError(f"Unsupported OS: {system}")


@contextmanager
def _ephemeral_age_keyfile(key: str):
    """age 鍵を一時ファイルに書き出し、終了後に確実に削除"""
    tmp = tempfile.NamedTemporaryFile(
        mode="w", prefix="age-", suffix=".key", delete=False
    )
    try:
        tmp.write(f"# age secret key\n{key}\n")
        tmp.close()
        os.chmod(tmp.name, 0o600)
        yield tmp.name
    finally:
        # 上書きしてから削除（メモリマップ対策）
        with open(tmp.name, "w") as f:
            f.write("\x00" * 256)
        Path(tmp.name).unlink(missing_ok=True)


def load_sops_env(
    encrypted_file: str = ".env.enc",
    use_keychain: bool = True,
) -> dict[str, str]:
    """SOPS 暗号化 .env を復号して環境変数にロード"""

    if use_keychain:
        age_key = _get_age_key_from_keychain()
        ctx = _ephemeral_age_keyfile(age_key)
    else:
        # KMS 利用時など鍵ファイル不要の場合
        from contextlib import nullcontext
        ctx = nullcontext(None)

    with ctx as keyfile:
        env = os.environ.copy()
        if keyfile:
            env["SOPS_AGE_KEY_FILE"] = keyfile

        result = subprocess.run(
            ["sops", "--decrypt",
             "--input-type", "dotenv",
             "--output-type", "dotenv",
             encrypted_file],
            capture_output=True, text=True, check=True,
            env=env,
        )

    secrets = {}
    for line in result.stdout.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")
        secrets[key.strip()] = value
        os.environ[key.strip()] = value

    return secrets


if __name__ == "__main__":
    secrets = load_sops_env()
    print(f"Loaded {len(secrets)} secrets")
```

### パターン3: AWS Secrets Manager 直接取得（本番環境推奨）

```python
# config_aws.py
"""
.env ファイルを使わず、AWS Secrets Manager から直接シークレットを取得。
最も安全 — ファイルシステムにシークレットが存在しない。
"""
import json
import os
import boto3
from functools import lru_cache


@lru_cache(maxsize=1)
def _get_client():
    return boto3.client("secretsmanager", region_name="ap-northeast-1")


def get_secret(name: str) -> str:
    """単一シークレットを取得"""
    resp = _get_client().get_secret_value(SecretId=name)
    return resp["SecretString"]


def load_secrets_from_aws(
    secret_name: str = "myapp/env",
    set_environ: bool = True,
) -> dict[str, str]:
    """
    Secrets Manager に JSON 形式で格納されたシークレットを一括取得。
    {"DATABASE_URL": "...", "API_KEY": "..."} の形式を想定。
    """
    raw = get_secret(secret_name)
    secrets = json.loads(raw)

    if set_environ:
        for key, value in secrets.items():
            os.environ[key] = str(value)

    return secrets


# --- Pydantic Settings 統合 ---
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    database_url: str = Field(alias="DATABASE_URL")
    api_key: str = Field(alias="API_KEY")
    debug: bool = False
    log_level: str = "INFO"

    @classmethod
    def from_aws(cls, secret_name: str = "myapp/env") -> "Settings":
        secrets = load_secrets_from_aws(secret_name, set_environ=False)
        return cls(**secrets)


if __name__ == "__main__":
    settings = Settings.from_aws()
    print(f"DB: {settings.database_url}")
```

### パターン4: 環境に応じた自動切り替え

```python
# config.py
"""
APP_ENV に応じて最適なシークレット取得方式を自動選択。

  development  → dotenvx + OS Keychain
  staging      → SOPS + age (Keychain)
  production   → AWS Secrets Manager（.env ファイル不要）
"""
import os

APP_ENV = os.getenv("APP_ENV", "development")


def load_config():
    if APP_ENV == "production":
        # 本番: ファイルシステムにシークレットを置かない
        from config_aws import load_secrets_from_aws
        load_secrets_from_aws("myapp/env/production")

    elif APP_ENV == "staging":
        # ステージング: SOPS + KMS（鍵ファイル不要）
        from config_sops import load_sops_env
        load_sops_env(".env.staging.enc", use_keychain=False)
        # ↑ KMS 利用時は use_keychain=False（IAMロールで認証）

    else:
        # 開発: dotenvx + OS Keychain
        try:
            from config_dotenvx import load_dotenvx_secure
            load_dotenvx_secure()
        except Exception:
            # フォールバック: python-dotenv
            from dotenv import load_dotenv
            load_dotenv()


load_config()
```

---

## 脅威シナリオ別の防御マッピング

| 脅威 | Layer 1 暗号化 | Layer 2 鍵の隔離 | Layer 3 アクセス制御 | Layer 4 検知 |
|------|:-:|:-:|:-:|:-:|
| **Git に平文 .env をコミット** | ✅ 暗号化で防御 | — | — | ✅ pre-commit フック |
| **リポジトリの不正公開** | ✅ 暗号化で防御 | — | — | ✅ gitleaks |
| **依存パッケージに悪意あるコード（サプライチェーン攻撃）** | ⚠️ 鍵が同居なら突破される | ✅ Keychain で認証要求 | ✅ ファイル権限 | ✅ 異常な外部通信検知 |
| **開発マシンへのマルウェア侵入** | ⚠️ 鍵が同居なら突破される | ✅ Keychain + Touch ID | ✅ TCC / AppArmor | ✅ Bitdefender + LuLu |
| **本番サーバへの侵入** | — | ✅ KMS / Secrets Manager（ファイルなし） | ✅ IAM 最小権限 | ✅ CloudTrail 監査 |
| **CI/CD パイプラインの侵害** | ✅ 暗号化で範囲限定 | ✅ GitHub Secrets | ✅ 最小権限トークン | ✅ Audit ログ |
| **退職者の鍵持ち出し** | — | ✅ KMS: IAM 削除で即座に無効化 | — | ✅ CloudTrail |

---

## クイックリファレンス

### dotenvx コマンド

| コマンド | 説明 |
|---------|------|
| `dotenvx encrypt` | `.env` を暗号化 |
| `dotenvx decrypt` | `.env` を復号 |
| `dotenvx encrypt -f .env.production` | 指定ファイルを暗号化 |
| `dotenvx run -- <command>` | 復号して環境変数注入 → コマンド実行 |
| `dotenvx get DATABASE_URL` | 特定の値だけ復号して取得 |

### SOPS コマンド（dotenv 形式）

| コマンド | 説明 |
|---------|------|
| `sops --encrypt --input-type dotenv --output-type dotenv .env > .env.enc` | 暗号化 |
| `sops --decrypt --input-type dotenv --output-type dotenv .env.enc > .env` | 復号 |
| `sops --input-type dotenv --output-type dotenv .env.enc` | エディタで編集 |
| `sops updatekeys .env.enc` | 鍵のローテーション |
| `sops --rotate --input-type dotenv --output-type dotenv -i .env.enc` | データキーのローテーション |

### 秘密鍵の Keychain 操作

| OS | 格納 | 取得 |
|----|------|------|
| **Mac** | `security add-generic-password -a $USER -s "名前" -w "鍵"` | `security find-generic-password -a $USER -s "名前" -w` |
| **Linux** | `echo "鍵" \| secret-tool store --label="名前" service svc account acc` | `secret-tool lookup service svc account acc` |
| **Windows** | `cmdkey /generic:"名前" /user:$USER /pass:"鍵"` | PowerShell `Get-StoredCredential` |
