# Pythonサプライチェーン攻撃対策：Dependency Cooldown（依存パッケージ猶予期間）実装ガイド

**作成日:** 2026年4月5日  
**対象:** Python開発者・LLMOps/AI開発チーム  
**背景:** 2026年3月のLiteLLM/axios同時多発サプライチェーン攻撃を受けた実務対策

---

## 1. Dependency Cooldownとは

Dependency Cooldown（依存パッケージ猶予期間）とは、**PyPIに公開されてから一定期間が経過していないパッケージのインストールを拒否する**セキュリティ機構である。

公開直後のパッケージを自動的にブロックすることで、セキュリティ研究者やPyPI管理者がマルウェアを検出・除去するための時間的余裕を確保する。2026年3月のLiteLLM攻撃（悪意あるバージョンが約5時間で除去された）のような事例では、3日間のクールダウンを設定していれば被害を完全に回避できた。

2026年4月2日、PyPI公式ブログがDependency Cooldownsを正式に推奨し、エコシステム全体での導入が加速している。

---

## 2. なぜ今Cooldownが必要なのか — 2026年3月の教訓

2026年3月19日〜31日の12日間に、5つの主要OSSプロジェクトが連続して侵害された。

| 日付 | プロジェクト | エコシステム | 攻撃手法 | 悪意あるバージョンの公開時間 |
|------|------------|------------|---------|------------------------|
| 3/19 | Trivy (Aqua Security) | Docker Hub / npm | GitHub Actionsタグポイズニング | 約5日 |
| 3/21 | Checkmarx AST | GitHub Actions | タグポイズニング | 不明 |
| 3/24 | **LiteLLM** | **PyPI** | **.pthファイル注入** | **約5時間** |
| 3/24 | Telnyx | PyPI | 認証情報窃取 | 数時間 |
| 3/31 | **axios** | **npm** | **postinstallフック** | **約3時間** |

いずれの攻撃も、悪意あるバージョンは数時間〜数日で除去されている。**7日間のクールダウンを設定していれば、これらすべてを自動的に回避できた。**

---

## 3. ツール別の設定方法

### 3.1 uv（推奨 — 最も完成度が高い）

uvは2025年12月のv0.9.17で相対日付によるクールダウンをサポートした、現時点で最も使いやすい実装。

**プロジェクト単位の設定（pyproject.toml）：**

```toml
[tool.uv]
exclude-newer = "P3D"    # 3日以内に公開されたパッケージを拒否
```

**グローバル設定（全プロジェクトに適用）：**

```toml
# ~/.config/uv/uv.toml
exclude-newer = "P7D"    # 7日間のクールダウン
```

**コマンドラインでの使用：**

```bash
# requirementsのコンパイル時にクールダウン適用
uv pip compile --exclude-newer "1 week" requirements.in -o requirements.txt

# 直接インストール時
uv pip install --exclude-newer "3 days" -r requirements.txt
```

**特定パッケージのクールダウン上書き（緊急パッチ用）：**

```toml
[tool.uv]
exclude-newer = "P7D"

# セキュリティパッチを即座に適用したいパッケージは個別に上書き
[[tool.uv.exclude-newer-package]]
name = "cryptography"
exclude-newer = "P0D"    # クールダウンなし
```

### 3.2 pip（v26.0以降 — 絶対日付のみ）

pip v26.0（2026年1月リリース）で`--uploaded-prior-to`オプションが追加された。ただし**絶対日付のみ**サポートで、相対日付（「3日前」）は未対応（pypa/pip#13674で議論中）。

**コマンドラインでの使用：**

```bash
# 絶対日付を指定（この日付以前に公開されたパッケージのみ許可）
pip install --uploaded-prior-to 2026-04-01T00:00:00Z -r requirements.txt

# dateコマンドと組み合わせて相対日付を実現
pip install \
  --uploaded-prior-to=$(date -d '-3days' -Idate) \
  -r requirements.txt

# macOSの場合
pip install \
  --uploaded-prior-to=$(date -v-3d +%Y-%m-%d) \
  -r requirements.txt
```

**pip.confでのグローバル設定：**

```ini
# ~/.config/pip/pip.conf (Linux/macOS)
# %APPDATA%\pip\pip.ini (Windows)
[global]
uploaded-prior-to = 2026-04-01
```

**自動更新スクリプト（Seth Larsonの手法）：**

pip.confの日付を毎日自動で更新するcronジョブを設定することで、擬似的な相対クールダウンを実現する。

```python
#!/usr/bin/env python3
# ~/.local/bin/pip-dependency-cooldown
# Credit: Seth Larson — MIT License
import datetime, sys, os, re

def main():
    pip_conf = os.path.abspath(os.path.expanduser(sys.argv[1]))
    days = int(sys.argv[2])

    with open(pip_conf) as f:
        data = f.read()

    pattern = re.compile(
        r"^uploaded-prior-to\s*=\s*2[0-9]{3}-[0-9]{2}-[0-9]{2}$",
        re.MULTILINE
    )
    if not pattern.search(data):
        return 1

    new_date = (
        datetime.date.today() - datetime.timedelta(days=days)
    ).strftime("%Y-%m-%d")
    data = pattern.sub(f"uploaded-prior-to = {new_date}", data)

    with open(pip_conf, "w") as f:
        f.write(data)

if __name__ == "__main__":
    sys.exit(main() or 0)
```

**cron設定（毎日9時に実行）：**

```bash
# Linux
(crontab -l 2>/dev/null; echo '0 9 * * * /usr/bin/python3 ~/.local/bin/pip-dependency-cooldown ~/.config/pip/pip.conf 7') | crontab -
```

**macOS（launchd）：**

```bash
# ~/Library/LaunchAgents/com.pip.dependency-cooldown.plist を作成
# 毎日9時に実行し、pip.confの日付を7日前に更新
```

**systemdタイマー（Linux）：**

```ini
# ~/.config/systemd/user/pip-dependency-cooldown.service
[Unit]
Description=Update pip dependency cooldown date

[Service]
ExecStart=/usr/bin/python3 %h/.local/bin/pip-dependency-cooldown %h/.config/pip/pip.conf 7

# ~/.config/systemd/user/pip-dependency-cooldown.timer
[Unit]
Description=Daily pip dependency cooldown update

[Timer]
OnCalendar=*-*-* 09:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
systemctl --user enable --now pip-dependency-cooldown.timer
```

### 3.3 pip v26.1（今後のリリース — 相対日付サポート予定）

PyPI公式ブログによると、pip v26.1（2026年4月リリース見込み）で相対日付のクールダウンがネイティブサポートされる予定。これが実現すれば以下のように設定できるようになる：

```ini
# ~/.config/pip/pip.conf（予定）
[global]
uploaded-prior-to = P3D    # cronジョブ不要になる
```

---

## 4. CI/CDパイプラインへの適用

### GitHub Actions

```yaml
# .github/workflows/ci.yml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install dependencies with cooldown
        run: |
          pip install uv
          uv pip install --exclude-newer "3 days" -r requirements.txt

      # または pip の場合
      - name: Install with pip cooldown
        run: |
          COOLDOWN_DATE=$(date -d '-3days' +%Y-%m-%d)
          pip install --uploaded-prior-to $COOLDOWN_DATE -r requirements.txt
```

### Dockerfile

```dockerfile
FROM python:3.12-slim

# uv を使う場合（推奨）
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock ./
RUN uv pip install --system --exclude-newer "3 days" -r pyproject.toml

# pip を使う場合
COPY requirements.txt ./
RUN COOLDOWN_DATE=$(date -d '-3days' +%Y-%m-%d) && \
    pip install --uploaded-prior-to $COOLDOWN_DATE \
                --only-binary :all: \
                --require-hashes \
                -r requirements.txt
```

---

## 5. Cooldownと組み合わせるべき追加対策

Cooldown単体では防げない攻撃パターンが存在する。多層防御が必要。

### 5.1 .pthファイル監査（LiteLLM攻撃対策）

Pythonの`.pth`ファイルはクールダウンで新規パッケージをブロックしても、**すでにインストール済みのパッケージが汚染された場合**には効果がない。定期的な監査が必要。

```bash
# site-packages内のすべての.pthファイルをリスト
python -c "
import site, os, glob
for d in site.getsitepackages():
    for f in glob.glob(os.path.join(d, '*.pth')):
        print(f)
        with open(f) as fh:
            content = fh.read()
            if 'import' in content or 'exec' in content:
                print(f'  ⚠️  WARNING: Contains executable code!')
            print(f'  Content: {content[:200]}')
"
```

### 5.2 ハッシュ検証

```bash
# requirements.txt にハッシュを含める
pip install --require-hashes -r requirements.txt

# ハッシュ付きrequirements.txtの生成
pip-compile --generate-hashes requirements.in -o requirements.txt

# uv の場合
uv pip compile --generate-hashes requirements.in -o requirements.txt
```

### 5.3 pip-auditによる脆弱性スキャン

```bash
pip install pip-audit
pip-audit                          # 現在の環境をスキャン
pip-audit -r requirements.txt      # ファイルからスキャン
```

### 5.4 wheelのみインストール（setup.py実行の回避）

```bash
# setup.py を一切実行しない（ソースディストリビューションを拒否）
pip install --only-binary :all: -r requirements.txt
```

注意：wheelが提供されていないパッケージではインストールが失敗する。それが意図的な動作であり、リスクを明示的に受け入れる場合のみ個別に許可する。

ただし、`--only-binary`は`.pth`ファイル攻撃（LiteLLM v1.82.8）は防げない。`.pth`ファイルはwheelにも含めることができるため。

---

## 6. クールダウンの限界と注意点

| 限界 | 説明 | 対処 |
|------|------|------|
| セキュリティパッチの遅延 | ゼロデイ修正が3〜7日間適用できない | 重要パッケージは個別にクールダウンを短縮（uvの`exclude-newer-package`） |
| すでにインストール済みのパッケージ | クールダウンは新規インストール時のみ有効 | `pip-audit`による定期スキャンを併用 |
| タイムゾーンの問題 | CIサーバー（UTC）とローカル環境のタイムゾーン差 | UTCで統一するか、余裕を持った日数を設定 |
| レジストリのタイムスタンプ依存 | PyPIが正確なアップロード時刻を報告する前提 | 現状ではPyPIは正確だが保証ではない |
| .pthファイル攻撃 | wheelに.pthを含めることが可能 | .pthファイルの定期監査が別途必要 |

---

## 7. 推奨設定まとめ — 今日やるべきこと

**開発マシン（最優先）：**

```toml
# pyproject.toml に追加
[tool.uv]
exclude-newer = "P3D"
```

uvを使っていない場合はpip.confに絶対日付を設定し、cronで毎日更新する。

**CI/CDパイプライン：**

```bash
uv pip install --exclude-newer "7 days" -r requirements.txt
# または
pip install --uploaded-prior-to=$(date -d '-7days' -Idate) \
            --only-binary :all: \
            --require-hashes \
            -r requirements.txt
```

**定期監査（週次）：**

```bash
pip-audit
python -c "import site, glob, os; [print(f) for d in site.getsitepackages() for f in glob.glob(os.path.join(d, '*.pth'))]"
```

---

## 8. 参考リンク

- PyPI公式ブログ「Incident Report: LiteLLM/Telnyx supply-chain attacks」(2026-04-02)
- Andrew Nesbitt「Package Managers Need to Cool Down」(2026-03-04)
- Seth Larson のpip cooldown自動更新スクリプト
- pip Issue #13674: 相対クールダウンのリクエスト
- uv ドキュメント: exclude-newer設定
- pip v26.0 リリースノート: --uploaded-prior-to
