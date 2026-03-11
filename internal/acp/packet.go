package acp

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
)

const (
	headerLen        = 0x20
	payloadOffset    = 40
	errorCodeOffset  = 28
	discoverKeyStart = 43
)

func parseHexBytes(in string, expectedLen int) ([]byte, error) {
	n := normalizeHex(in)
	if len(n) != expectedLen*2 {
		return nil, fmt.Errorf("invalid hex length: want %d bytes", expectedLen)
	}
	out, err := hex.DecodeString(n)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func formatMAC(b []byte) string {
	parts := make([]string, 0, len(b))
	for _, one := range b {
		parts = append(parts, fmt.Sprintf("%02X", one))
	}
	return strings.Join(parts, ":")
}

func setHeader(buf []byte, cmd uint16, connID, targetMAC string, payloadSize byte) error {
	if len(buf) < headerLen {
		return errors.New("packet buffer too short")
	}
	conn, err := parseHexBytes(connID, 6)
	if err != nil {
		return fmt.Errorf("invalid connID: %w", err)
	}
	mac, err := parseHexBytes(targetMAC, 6)
	if err != nil {
		return fmt.Errorf("invalid target MAC: %w", err)
	}

	buf[0] = headerLen
	buf[4] = 0x08
	buf[6] = 0x01
	buf[8] = byte(cmd & 0xFF)
	buf[9] = byte((cmd >> 8) & 0xFF)
	buf[10] = payloadSize
	copy(buf[16:22], conn)
	copy(buf[22:28], mac)
	return nil
}

func buildDiscover(connID, targetMAC string) ([]byte, error) {
	buf := make([]byte, 72)
	return buf, setHeader(buf, cmdDiscover, connID, targetMAC, 0x28)
}

func buildSpecialAuth(connID, targetMAC string, encrypted []byte, special byte) ([]byte, error) {
	if len(encrypted) < 8 {
		return nil, errors.New("encrypted password must be at least 8 bytes")
	}
	buf := make([]byte, 72)
	if err := setHeader(buf, cmdSpecial, connID, targetMAC, 0x28); err != nil {
		return nil, err
	}
	buf[32] = special
	copy(buf[payloadOffset:payloadOffset+8], encrypted[:8])
	return buf, nil
}

func buildExec(connID, targetMAC, cmdline string) ([]byte, error) {
	if len(cmdline) > 210 {
		return nil, errors.New("command line too long (>210 chars)")
	}
	buf := make([]byte, len(cmdline)+44)
	if err := setHeader(buf, cmdExec, connID, targetMAC, byte(len(cmdline)+12)); err != nil {
		return nil, err
	}
	buf[32] = byte(len(cmdline))
	buf[36] = 0x03
	copy(buf[payloadOffset:], []byte(cmdline))
	return buf, nil
}

type DiscoveryReply struct {
	HostName   string
	IP         string
	MAC        string
	Product    string
	ProductID  string
	Firmware   string
	KeyHex     string
	Formatted  string
	RawErrCode uint32
}

func parseDiscoveryReply(buf []byte) DiscoveryReply {
	r := DiscoveryReply{RawErrCode: parseErrorCode(buf)}
	if len(buf) < 312 {
		return r
	}
	ip := []byte{buf[35], buf[34], buf[33], buf[32]}
	if ipAddr := net.IP(ip); ipAddr != nil {
		r.IP = ipAddr.String()
	}
	r.HostName = readCString(buf, 48)
	r.Product = readCString(buf, 80)
	r.Firmware = fmt.Sprintf("%d%d.%d%d", buf[187], buf[188], buf[189], buf[190])
	r.ProductID = fmt.Sprintf("%d%d%d%d", buf[195], buf[194], buf[193], buf[192])
	r.MAC = formatMAC(buf[311:317])
	r.KeyHex = fmt.Sprintf("%02X%02X%02X%02X", buf[47], buf[46], buf[45], buf[44])
	r.Formatted = fmt.Sprintf("Found:\t%s (%s) \t%s (ID=%s) \tmac: %s\tFirmware=  %s\tKey=%s", r.HostName, r.IP, r.Product, r.ProductID, r.MAC, r.Firmware, r.KeyHex)
	return r
}

func parseErrorCode(buf []byte) uint32 {
	if len(buf) < errorCodeOffset+4 {
		return 0xFFFFFFFF
	}
	return uint32(buf[28]) | uint32(buf[29])<<8 | uint32(buf[30])<<16 | uint32(buf[31])<<24
}

func parseReplyType(buf []byte) uint16 {
	if len(buf) < 10 {
		return 0
	}
	return uint16(buf[8]) | uint16(buf[9])<<8
}

func readCString(buf []byte, start int) string {
	if start >= len(buf) {
		return ""
	}
	end := start
	for end < len(buf) && buf[end] != 0x00 {
		end++
	}
	return string(buf[start:end])
}
