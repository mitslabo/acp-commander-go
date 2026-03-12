# acp-commander-go

[![Release](https://img.shields.io/github/v/release/mitsucodes/acp-commander-go?display_name=tag&sort=semver&cacheSeconds=300)](https://github.com/mitsucodes/acp-commander-go/releases)

This release also adds a new `-x` option allowing the CLI to serve a local file over HTTP and instruct a target LinkStation to fetch it via `wget` (falling back to `busybox wget`).
[![Downloads](https://img.shields.io/github/downloads/mitsucodes/acp-commander-go/total)](https://github.com/mitsucodes/acp-commander-go/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/mitsucodes/acp-commander-go)](https://github.com/mitsucodes/acp-commander-go/blob/main/go.mod)

This is an independent project that reimplements the functionality of `acp_commander.jar` in Go.

## Fork Source / Credits

This implementation is ported from the following Java project:

- Upstream project: https://github.com/Stonie/acp-commander
- Related historical info (mentioned in the README):
  - https://www.nas-central.org/
  - http://linkstationwiki.net/

## Current Scope (WIP)

The major features implemented so far are:

- `-f` discover
- Authentication flow (`Discover -> EnOneCmd -> Auth`)
- `-c` single command execution
- `-x` copy local file via HTTP/wget to remote path
- `-o` openbox (`telnetd` + `passwd -d root`)

Unsupported options return an explicit error.

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

Example:

```bash
go run ./cmd/acp-commander -t 192.168.1.11 -pw <admin_password> -c "uname -a"
```

Copy example:

```bash
go run ./cmd/acp-commander -t 192.168.1.11 -pw <admin_password> -x ./local.bin=/tmp/remote.bin
```