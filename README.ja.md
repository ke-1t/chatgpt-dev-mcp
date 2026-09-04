# chatgpt-dev-mcp

[English README](README.md)

`chatgpt-dev-mcp` は、ChatGPT からローカルの開発リポジトリを安全に扱うための MCP コントロールプレーンです。`coding-tools-mcp` の安全なローカル実行機能の上に、登録済みworkspace、権限profile、承認、監査、並列開発session、verification、Git closeout などの統制を追加します。

## 役割

このプロジェクトの役割は「コードを書くAIそのもの」ではなく、ChatGPT が複数のローカルprojectを安全に管理するための境界を提供することです。

- 登録済みprojectだけをworkspaceとして扱う
- `READ_ONLY` / `DEVELOPMENT` などの権限境界を保つ
- writer lease と stale-base 検証で競合書き込みを防ぐ
- verification / security audit / integration の証拠を保持する
- commit / push などのdelivery操作を明示的な境界に分離する
- secret、任意shell、危険なfilesystem操作を既定で拒否する

通常のcoding agentによる実装作業は、そのagent自身のnative harnessで行います。coding agentからDevMCPを通常のcoding harnessとして呼ぶことは想定していません。repo内のagent共通ルールは [`AGENTS.md`](AGENTS.md) を参照してください。

## 全体像

```text
User
  │
  ▼
ChatGPT
  │
  ├── DevMCP ── workspace / policy / audit / integration / delivery control
  │
  └── Coding agents ─── native filesystem / shell / Git / test / build / implementation
```

DevMCPを利用する場合の詳細な構造と境界は [`ARCHITECTURE.md`](ARCHITECTURE.md) が現在の正本です。

## 安全境界

- workspace selector は任意pathではなくregistry IDを使用します。
- `READ_ONLY` が既定です。
- sensitive path、credential-like file、symlink escape、workspace外pathを拒否します。
- arbitrary shell command は公開しません。
- local config registry はoperator-ownedです。
- Git commit / push / integration は通常の編集とは別の境界です。
- force push、reset、clean、arbitrary remote変更、secret操作などは通常surfaceの対象外です。
- verification receipt やapproval tokenは外部成功の証明として扱いません。
- `development.session.reconcile_stale_state` はRegistry専用の2段階reconciliationです。DevMCP管理下のsession/task/lease/process/Git証跡を読み、immutableなstate digestをpinしてからexecute時に再確認します。dirty worktreeはarchive/provenanceを保存したうえで保持し、missing worktreeはsource・allowlist root・不在証跡を検証できる場合だけ `cleanup_candidate` としてtombstone化します。worktree削除・Git prune・missingを成功扱いする推測は行いません。legacy rootは `LOCAL_DEV_MCP_LEGACY_WORKTREE_ROOTS` で明示したものだけを対象にします。
- `development.session.archive` は、sourceのdevice/inodeをそのまま検証できなくなった一方で、Git履歴とmanaged worktreeを独立に検証できるstale session向けの非破壊retained-evidence経路です。ownerのsemantic dispositionを明示的に確認し、dirty bytesをarchiveして検証し、元のsidecar bytesを保持したうえで `EVIDENCE_RETAINED_TERMINAL` と `cleanup_candidate` をreceipt付きで記録します。source identityの修復、patchのintegration、worktreeの削除/GCは行わず、active task・lease・process、未解決のdirty状態、identity conflict、unknown evidenceは引き続きblockします。
- `runtime.candidate.activate` は、schema 14・76 tools・healthy doctor/canary・Git HEAD・DB fingerprint・cleanでschema互換なrollback authorityを確認したうえで、1つのruntime candidateを人間承認でactivateするRegistry capabilityです。通常のwrapperは未接続のまま保持し、operator管理のv26環境が有効なときだけ、正式なcurrent-runtime readerと固定deployment executorを注入します。caller指定のpathやcommandを再起動権限にはしません。
- `development.evidence.import_generation` は、allowlistされたprivate source DBから指定sessionと依存closureだけをdestinationへtransactionalにimportする人間承認capabilityです。durable identityとprovenanceを保持し、source DB/sidecarのcopy・replace・downgrade・delete・手編集を行いません。sourceが読み取り中に変化した場合はdestination書込み前にfail closedします。

詳細は [`SECURITY_MODEL.md`](SECURITY_MODEL.md) と [`SECURITY.md`](SECURITY.md) を参照してください。

## インストール

```sh
git clone https://github.com/ke-1t/chatgpt-dev-mcp.git chatgpt-dev-mcp
cd chatgpt-dev-mcp
uv venv .venv
uv pip install -e .
```

registryの初期設定例:

```sh
mkdir -p "$HOME/.config/local-dev-mcp"
cp config.example.json "$HOME/.config/local-dev-mcp/config.json"
```

最初は必ずdisposableなrepositoryで動作確認してください。

## Registry

既定のregistryは `~/.config/local-dev-mcp/config.json` です。workspaceは明示的に登録されたproject IDだけを選択できます。

```json
{
  "version": 1,
  "roots": [
    {
      "id": "developer",
      "path": "~/Developer",
      "mode": "PROJECT_DISCOVERY"
    }
  ],
  "workspaces": {
    "sample": {
      "path": "/absolute/path/to/sample-repo",
      "profile": "DEVELOPMENT",
      "commands": {
        "test": "pytest",
        "lint": "ruff check .",
        "build": "npm run build"
      }
    }
  }
}
```

## 基本的な利用フロー

読み取り中心の利用:

```text
workspace_list
  -> workspace_open
  -> read / search / git status / diff
```

管理されたisolated developmentを使う場合:

```text
registered project
  -> managed DEVELOPMENT session
  -> path/resource scoped lease
  -> patch / test / diff
  -> verification + security evidence
  -> integration preflight
  -> canonical integration
```

実際の詳細なtool契約は英語版 [`README.md`](README.md) と [`ARCHITECTURE.md`](ARCHITECTURE.md) を参照してください。

## Coding agentsとの役割分担

Codex、Claude Code、Cursor、Gemini CLIなどのcoding agentは、通常のcoding作業についてDevMCPを経由する必要はありません。

```text
Coding agent native harness
├── repository inspection
├── file edit
├── shell
├── test / lint / build
├── Git / worktree
└── subagents

DevMCP
├── ChatGPT側のproject governance
├── cross-workspace state
├── audit / receipt
├── managed integration
└── project固有のpolicy boundary
```

repo内のcoding-agent共通常設ルールは [`AGENTS.md`](AGENTS.md) に置きます。Claude CodeとGemini CLIには薄いbridgeだけを置き、アーキテクチャや運用手順をagent別ファイルへ複製せず、必要な正本へリンクする方針です。

## Verification

高速な確認:

```sh
.venv/bin/python scripts/verify_fast.py
```

全体確認:

```sh
.venv/bin/python scripts/verify_full.py
```

tool surface、policy、transport、persistence、Git delivery、安全境界を変更した場合はfull verificationを優先します。

## ドキュメント構成

| ファイル | 役割 |
| --- | --- |
| `README.md` | 英語の利用・仕様ガイド |
| `README.ja.md` | 日本語の概要・利用ガイド |
| `AGENTS.md` | coding agent共通の短い常設ルールと参照先 |
| `ARCHITECTURE.md` | 現在のsystem構造、責務、data/control flow、境界の正本 |
| `OPERATIONS_GUIDE.md` | install、runtime、health、restart、rollbackなどの運用手順 |
| `SECURITY_MODEL.md` | trust boundary、安全不変条件、risk/approval model |
| `SECURITY.md` | vulnerability reportingなど公開security policy |
| `CONTRIBUTING.md` | contributor向け開発・verification規約 |
| `docs/` | 個別のdesign、spec、plan、履歴 |

`AGENTS.md` を巨大なマニュアルにはせず、詳細は上記の正本へ分離します。

## ライセンスとupstream

このrepositoryは `coding-tools-mcp` のforkではなく独立したwrapperです。依存関係とthird-party noticeは [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) を参照してください。
