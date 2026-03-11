package acp

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

type Client struct {
	TargetIP    string
	Port        int
	ConnID      string
	TargetMAC   string
	Password    string
	BindIP      string
	DebugLevel  int
	Timeout     time.Duration
	Resend      int
	Quiet       bool
	HaveKey     bool
	EnOne       bool
	LastError   uint32
	key         [4]byte
	apServdWord string
}

func NewClient(targetIP string) *Client {
	return &Client{
		TargetIP:    targetIP,
		Port:        DefaultPort,
		ConnID:      randomConnID(),
		TargetMAC:   "FFFFFFFFFFFF",
		Timeout:     time.Duration(DefaultTimeout) * time.Millisecond,
		Resend:      DefaultResend,
		apServdWord: "ap_servd",
	}
}

func randomConnID() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	buf := make([]byte, 6)
	_, _ = r.Read(buf)
	return fmt.Sprintf("%02X%02X%02X%02X%02X%02X", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5])
}

func (c *Client) SetConnID(connID string) error {
	_, err := parseHexBytes(connID, 6)
	if err != nil {
		return err
	}
	c.ConnID = normalizeHex(connID)
	return nil
}

func (c *Client) SetTargetMAC(mac string) error {
	_, err := parseHexBytes(mac, 6)
	if err != nil {
		return err
	}
	c.TargetMAC = normalizeHex(mac)
	return nil
}

func (c *Client) Find() ([]DiscoveryReply, error) {
	if strings.TrimSpace(c.TargetIP) == "" {
		c.TargetIP = "255.255.255.255"
	}
	pkt, err := buildDiscover(c.ConnID, c.TargetMAC)
	if err != nil {
		return nil, err
	}
	conn, err := c.openUDP()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", c.TargetIP, c.Port))
	if err != nil {
		return nil, err
	}
	if err := conn.SetWriteDeadline(time.Now().Add(c.Timeout)); err != nil {
		return nil, err
	}
	if _, err := conn.WriteToUDP(pkt, addr); err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	results := make([]DiscoveryReply, 0, 4)
	deadline := time.Now().Add(c.Timeout)
	for {
		if err := conn.SetReadDeadline(deadline); err != nil {
			break
		}
		buf := make([]byte, 4096)
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break
			}
			return nil, err
		}
		reply := parseDiscoveryReply(buf[:n])
		if reply.Formatted == "" || seen[reply.Formatted] {
			continue
		}
		seen[reply.Formatted] = true
		results = append(results, reply)
	}
	return results, nil
}

func (c *Client) Discover(setTargetData bool) (DiscoveryReply, error) {
	pkt, err := buildDiscover(c.ConnID, c.TargetMAC)
	if err != nil {
		return DiscoveryReply{}, err
	}
	replyBuf, err := c.sendAndReceive(pkt, 1)
	if err != nil {
		if setTargetData && isLikelyTimeout(err) {
			if fallback, ok := c.discoverViaBroadcastByIP(); ok {
				if setTargetData {
					if fallback.MAC != "" {
						_ = c.SetTargetMAC(fallback.MAC)
					}
					if fallback.KeyHex != "" {
						key, keyErr := parseHexBytes(fallback.KeyHex, 4)
						if keyErr == nil {
							copy(c.key[:], key)
							c.HaveKey = true
						}
					}
				}
				return fallback, nil
			}
		}
		return DiscoveryReply{}, err
	}
	r := parseDiscoveryReply(replyBuf)
	c.LastError = parseErrorCode(replyBuf)
	if setTargetData {
		if r.MAC != "" {
			_ = c.SetTargetMAC(r.MAC)
		}
		if r.KeyHex != "" {
			key, keyErr := parseHexBytes(r.KeyHex, 4)
			if keyErr == nil {
				copy(c.key[:], key)
				c.HaveKey = true
			}
		}
	}
	return r, nil
}

func (c *Client) discoverViaBroadcastByIP() (DiscoveryReply, bool) {
	originalTarget := c.TargetIP
	c.TargetIP = "255.255.255.255"
	defer func() { c.TargetIP = originalTarget }()

	found, err := c.Find()
	if err != nil {
		return DiscoveryReply{}, false
	}
	for _, one := range found {
		if strings.EqualFold(strings.TrimSpace(one.IP), strings.TrimSpace(originalTarget)) {
			return one, true
		}
	}
	return DiscoveryReply{}, false
}

func isLikelyTimeout(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout")
}

func (c *Client) EnOneCmd() (string, error) {
	if !c.HaveKey {
		return "", errors.New("no encryption key available; run discover first")
	}
	enc, err := EncryptACPPassword(c.apServdWord, c.key[:])
	if err != nil {
		return "", err
	}
	pkt, err := buildSpecialAuth(c.ConnID, c.TargetMAC, enc, specialEnOneCmd)
	if err != nil {
		return "", err
	}
	raw, err := c.sendAndReceive(pkt, c.Resend)
	if err != nil {
		return "", err
	}
	c.LastError = parseErrorCode(raw)
	if c.LastError == 0 {
		c.EnOne = true
	}
	return errorString(c.LastError), nil
}

func (c *Client) Auth() (string, error) {
	if !c.HaveKey {
		return "", errors.New("no encryption key available; run discover first")
	}
	enc, err := EncryptACPPassword(c.Password, c.key[:])
	if err != nil {
		return "", err
	}
	pkt, err := buildSpecialAuth(c.ConnID, c.TargetMAC, enc, specialAuth)
	if err != nil {
		return "", err
	}
	raw, err := c.sendAndReceive(pkt, c.Resend)
	if err != nil {
		return "", err
	}
	c.LastError = parseErrorCode(raw)
	return errorString(c.LastError), nil
}

func (c *Client) Command(cmdline string, resend int) (string, error) {
	if resend <= 0 {
		resend = c.Resend
	}
	pkt, err := buildExec(c.ConnID, c.TargetMAC, cmdline)
	if err != nil {
		return "", err
	}
	raw, err := c.sendAndReceive(pkt, resend)
	if err != nil {
		return "", err
	}
	c.LastError = parseErrorCode(raw)
	if parseReplyType(raw) != 0xCA10 {
		return errorString(c.LastError), nil
	}
	reply := readCString(raw, payloadOffset)
	if strings.EqualFold(reply, "**no message**") || reply == "" {
		return fmt.Sprintf("OK (%s)", errorString(c.LastError)), nil
	}
	return reply, nil
}

func (c *Client) OpenBox() error {
	if _, err := c.Command("telnetd", 3); err != nil {
		return err
	}
	_, err := c.Command("passwd -d root", 3)
	return err
}

func (c *Client) sendAndReceive(packet []byte, repeat int) ([]byte, error) {
	if repeat <= 0 {
		repeat = c.Resend
	}
	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", c.TargetIP, c.Port))
	if err != nil {
		return nil, err
	}
	var lastErr error
	for i := 1; i <= repeat; i++ {
		conn, err := c.openUDP()
		if err != nil {
			lastErr = err
			continue
		}
		if err := conn.SetWriteDeadline(time.Now().Add(c.Timeout)); err != nil {
			conn.Close()
			lastErr = err
			continue
		}
		if _, err := conn.WriteToUDP(packet, addr); err != nil {
			conn.Close()
			lastErr = err
			continue
		}
		buf := make([]byte, 4096)
		if err := conn.SetReadDeadline(time.Now().Add(c.Timeout)); err != nil {
			conn.Close()
			lastErr = err
			continue
		}
		n, _, err := conn.ReadFromUDP(buf)
		conn.Close()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && i == repeat {
				lastErr = fmt.Errorf("timeout waiting for UDP response from %s:%d (local bind %s)", c.TargetIP, c.Port, localAddrString(conn))
				continue
			}
			lastErr = err
			continue
		}
		return buf[:n], nil
	}
	if lastErr == nil {
		lastErr = errors.New("timeout while waiting for response")
	}
	return nil, lastErr
}

func (c *Client) openUDP() (*net.UDPConn, error) {
	if strings.TrimSpace(c.BindIP) == "" {
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	}
	bindAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:0", c.BindIP))
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp4", bindAddr)
}

func localAddrString(conn *net.UDPConn) string {
	if conn == nil {
		return "unknown"
	}
	addr := conn.LocalAddr()
	if addr == nil {
		return "unknown"
	}
	return addr.String()
}
