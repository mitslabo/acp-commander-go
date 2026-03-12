package acp

import "testing"

func TestBuildExecPacketShape(t *testing.T) {
	pkt, err := buildExec("001122334455", "FFFFFFFFFFFF", "id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkt) != 46 {
		t.Fatalf("unexpected packet length: %d", len(pkt))
	}
	if pkt[0] != 0x20 || pkt[4] != 0x08 || pkt[6] != 0x01 {
		t.Fatalf("unexpected header bytes: %02x %02x %02x", pkt[0], pkt[4], pkt[6])
	}
	if got := uint16(pkt[8]) | uint16(pkt[9])<<8; got != 0x8A10 {
		t.Fatalf("unexpected command code: 0x%04X", got)
	}
	if pkt[32] != 0x02 || pkt[36] != 0x03 {
		t.Fatalf("unexpected command payload markers: %02x %02x", pkt[32], pkt[36])
	}
	if string(pkt[40:42]) != "id" {
		t.Fatalf("unexpected command string: %q", string(pkt[40:42]))
	}
}
