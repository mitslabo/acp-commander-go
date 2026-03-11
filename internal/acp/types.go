package acp

import (
	"fmt"
	"strings"
)

const (
	DefaultPort    = 22936
	DefaultTimeout = 5000
	DefaultResend  = 2
)

const (
	cmdDiscover = 0x8020
	cmdChangeIP = 0x8030
	cmdSpecial  = 0x80A0
	cmdExec     = 0x8A10
)

const (
	specialAuth     = 0x0C
	specialEnOneCmd = 0x0D
)

var errorCodeText = map[uint32]string{
	0x00000000: "ACP_STATE_OK",
	0x80000000: "ACP_STATE_MALLOC_ERROR",
	0x80000001: "ACP_STATE_PASSWORD_ERROR",
	0x80000002: "ACP_STATE_NO_CHANGE",
	0x80000003: "ACP_STATE_MODE_ERROR",
	0x80000004: "ACP_STATE_CRC_ERROR",
	0x80000005: "ACP_STATE_NOKEY",
	0x80000006: "ACP_STATE_DIFFMODEL",
	0x80000007: "ACP_STATE_NOMODEM",
	0x80000008: "ACP_STATE_COMMAND_ERROR",
	0x80000009: "ACP_STATE_NOT_UPDATE",
	0x8000000A: "ACP_STATE_PERMIT_ERROR",
	0x8000000B: "ACP_STATE_OPEN_ERROR",
	0x8000000C: "ACP_STATE_READ_ERROR",
	0x8000000D: "ACP_STATE_WRITE_ERROR",
	0x8000000E: "ACP_STATE_COMPARE_ERROR",
	0x8000000F: "ACP_STATE_MOUNT_ERROR",
	0x80000010: "ACP_STATE_PID_ERROR",
	0x80000011: "ACP_STATE_FIRM_TYPE_ERROR",
	0x80000012: "ACP_STATE_FORK_ERROR",
	0xFFFFFFFF: "ACP_STATE_FAILURE",
}

func errorString(code uint32) string {
	if v, ok := errorCodeText[code]; ok {
		return v
	}
	return fmt.Sprintf("ACP_STATE_UNKNOWN_ERROR (%08X)", code)
}

func normalizeHex(s string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))
}
