# acp-commander-go

`acp_commander.jar` の機能を Go で再実装するための独立プロジェクトです。

## Fork Source / Credits

この実装は、以下の Java プロジェクトをベースに移植しています。

- Upstream project: https://github.com/Stonie/acp-commander
- Related historical info (README記載):
  - https://www.nas-central.org/
  - http://linkstationwiki.net/

## Current Scope (WIP)

現時点で実装済みの主要機能:

- `-f` discover
- 認証フロー (`Discover -> EnOneCmd -> Auth`)
- `-c` 単発コマンド実行
- `-o` openbox (`telnetd` + `passwd -d root`)

未対応オプションはエラーとして明示します。

## Build / Test

```bash
go test ./...
go build ./...
```

CLI cross-build (CGO disabled, stripped):

```powershell
pwsh -File .\scripts\build-cli.ps1
```

Artifacts are generated in `dist/`:

- `acp-commander_windows_amd64.exe`
- `acp-commander_linux_amd64`
- `acp-commander_linux_arm64`
- `acp-commander_linux_arm`

## Run

```bash
go run ./cmd/acp-commander -h
```

例:

```bash
go run ./cmd/acp-commander -t 192.168.1.11 -pw <admin_password> -c "uname -a"
```
