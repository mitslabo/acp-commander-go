package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"acp-commander/internal/acp"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}

// guessLocalIP attempts to determine the local address used to reach the
// given destination by opening a UDP socket.  It is a quick fallback when a
// more accurate interface-based search fails.
func guessLocalIP(dest string) (string, error) {
	conn, err := net.Dial("udp", dest+":80")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if udpAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return udpAddr.IP.String(), nil
	}
	return "", errors.New("unable to determine local IP from connection")
}

// findLocalIP looks through the machine's network interfaces to pick an
// address that is in the same network as the destination.  This is more
// reliable on multi‑homed hosts than UDP dialing.
func findLocalIP(dest string) (string, error) {
	destIP := net.ParseIP(dest)
	if destIP == nil {
		return "", fmt.Errorf("invalid destination IP %s", dest)
	}
	if destIP.To4() == nil {
		return "", errors.New("only IPv4 is supported for copy")
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			var ipnet *net.IPNet
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				ipnet = v
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.To4() == nil {
				continue
			}
			if ipnet != nil && ipnet.Contains(destIP) {
				return ip.String(), nil
			}
		}
	}
	// fallback
	return guessLocalIP(dest)
}

func run(args []string) error {
	if !strings.HasPrefix(os.Getenv("ACP_DEBUG"), "") {
		fmt.Printf("DEBUG: run args=%#v\n", args)
	}
	if len(args) == 0 || hasAny(args, "-h", "--h", "-help", "--help", "-u", "--usage", "-v", "--v", "-?", "--?") {
		usage()
		return nil
	}

	target := getParamValue(args, "-t", "")
	if target == "" && hasParam(args, "-f") {
		target = "255.255.255.255"
	}
	if target == "" {
		return errors.New("you didn't specify a target; parameter '-t target' is missing")
	}

	client := acp.NewClient(target)
	client.Quiet = hasParam(args, "-q")
	client.BindIP = getParamValue(args, "-b", "")
	if v := getParamValue(args, "-p", ""); v != "" {
		port, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("invalid port: %s", v)
		}
		client.Port = port
	}
	if v := getParamValue(args, "-i", ""); v != "" {
		if err := client.SetConnID(v); err != nil {
			return err
		}
	}
	if v := getParamValue(args, "-m", ""); v != "" {
		if err := client.SetTargetMAC(v); err != nil {
			return err
		}
	}
	if hasParam(args, "-d1") {
		client.DebugLevel = 1
	}
	if hasParam(args, "-d2") {
		client.DebugLevel = 2
	}
	if hasParam(args, "-d3") {
		client.DebugLevel = 3
	}
	if v := getParamValue(args, "-timeout", ""); v != "" {
		ms, err := strconv.Atoi(v)
		if err != nil {
			return err
		}
		client.Timeout = time.Duration(ms) * time.Millisecond
	}

	password := getParamValue(args, "-pw", "")
	cmdline := getParamValue(args, "-c", "")
	copySpec := getParamValue(args, "-x", "") // local=remote
	if copySpec != "" && !client.Quiet {
		fmt.Printf("copy spec: %s\n", copySpec)
	}
	openBox := hasParam(args, "-o")
	findLS := hasParam(args, "-f")
	needAuth := (openBox || cmdline != "" || copySpec != "") && !hasParam(args, "-na")
	needExplicitAuth := hasParam(args, "-auth")

	if !client.Quiet {
		fmt.Printf("Using target:\t%s\n", client.TargetIP)
		fmt.Printf("Using connID:\t%s\n", client.ConnID)
		fmt.Printf("Using MAC:\t%s\n", client.TargetMAC)
	}

	if findLS {
		fmt.Println("Sending ACP-Disover packet...")
		found, err := client.Find()
		if err != nil {
			return err
		}
		for _, one := range found {
			fmt.Println(one.Formatted)
		}
		fmt.Printf("Found %d linkstation(s).\n", len(found))
	}

	if needAuth || needExplicitAuth {
		fmt.Println("Starting authentication procedure...")
		disc, err := client.Discover(true)
		if err != nil {
			return err
		}
		if disc.Formatted != "" {
			fmt.Println(disc.Formatted)
		}

		en1, err := client.EnOneCmd()
		if err != nil {
			return err
		}
		fmt.Printf("Trying to authenticate EnOneCmd...\t%s\n", en1)

		if password != "" {
			client.Password = password
			authResult, err := client.Auth()
			if err != nil {
				return err
			}
			fmt.Printf("Trying to authenticate with admin password...\t%s\n", authResult)
		}
	}

	if openBox {
		out, err := client.Command("telnetd", 3)
		if err != nil {
			return err
		}
		fmt.Printf("start telnetd...\t%s\n", out)
		out, err = client.Command("passwd -d root", 3)
		if err != nil {
			return err
		}
		fmt.Printf("Reset root pwd...\t%s\n", out)
		fmt.Println("You can now telnet to your box as user 'root' providing no / an empty password.")
	}

	if cmdline != "" {
		trimmed := strings.Trim(cmdline, "\"")
		out, err := client.Command(trimmed, 1)
		if err != nil {
			return err
		}
		fmt.Printf(">%s\n%s\n", trimmed, out)
	}

	if copySpec != "" {
		parts := strings.SplitN(copySpec, "=", 2)
		if len(parts) != 2 {
			return errors.New("invalid -x syntax; expected local=remote")
		}
		localPath := parts[0]
		remotePath := parts[1]

		// ensure local file exists
		fi, err := os.Stat(localPath)
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return fmt.Errorf("%s is a directory", localPath)
		}

		// determine which local IP the target can reach.  respect explicit
		// bind option if provided (--bind/-b).
		localIP := client.BindIP
		if localIP == "" {
			var err error
			localIP, err = findLocalIP(client.TargetIP)
			if err != nil {
				return fmt.Errorf("unable to determine local IP: %w", err)
			}
		}

		ln, err := net.Listen("tcp", localIP+":0")
		if err != nil {
			return err
		}
		defer ln.Close()
		port := ln.Addr().(*net.TCPAddr).Port
		dir := filepath.Dir(localPath)
		file := filepath.Base(localPath)
		srvErr := make(chan error, 1)
		go func() {
			srvErr <- http.Serve(ln, http.FileServer(http.Dir(dir)))
		}()
		// give server a moment to start or fail
		select {
		case err := <-srvErr:
			return err
		case <-time.After(50 * time.Millisecond):
		}

		url := fmt.Sprintf("http://%s:%d/%s", localIP, port, file)
		if !client.Quiet {
			fmt.Printf("serving %s on %s (bind %s) and instructing remote to fetch\n", localPath, url, localIP)
		}
		cmd := fmt.Sprintf("wget -O %s %s || busybox wget -O %s %s", remotePath, url, remotePath, url)
		out, err := client.Command(cmd, 1)
		if err != nil {
			return err
		}
		fmt.Printf(">%s\n%s\n", cmd, out)
	}

	for _, unsupported := range []string{"-s", "-cb", "-reboot", "-shutdown", "-save", "-load", "-ip", "-addons", "-diag", "-gui"} {
		if hasParam(args, unsupported) {
			return fmt.Errorf("option %s is not yet supported in Go reimplementation", unsupported)
		}
	}

	return nil
}

func hasParam(args []string, key string) bool {
	for _, one := range args {
		if strings.EqualFold(one, key) {
			return true
		}
	}
	return false
}

func hasAny(args []string, keys ...string) bool {
	for _, key := range keys {
		if hasParam(args, key) {
			return true
		}
	}
	return false
}

func getParamValue(args []string, key, fallback string) string {
	for i := 0; i < len(args); i++ {
		if strings.EqualFold(args[i], key) {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				return args[i+1]
			}
			return fallback
		}
	}
	return fallback
}

func usage() {
	fs := flag.NewFlagSet("acp-commander", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fmt.Println("acp-commander (Go reimplementation, WIP)")
	fmt.Println("usage: acp-commander -t target [options]")
	fmt.Println("  -f               find/discover linkstations")
	fmt.Println("  -pw <password>   admin password")
	fmt.Println("  -c <command>     send ACP command")
	fmt.Println("  -x <local=remote> copy local file to remote using HTTP/wget")
	fmt.Println("  -o               open box (telnetd + passwd -d root)")
	fmt.Println("  -t <target>      target IP/hostname")
	fmt.Println("  -p <port>        UDP port (default 22936)")
	fmt.Println("  -m <mac>         target MAC (default FF:FF:FF:FF:FF:FF)")
	fmt.Println("  -i <connid>      connection ID (6-byte hex)")
	fmt.Println("  -b <localIP>     bind to local IP")
	fmt.Println("  -d1|-d2|-d3      debug level")
	fmt.Println("  -q               quiet")
	_, _ = fs.Output().Write([]byte(""))
}
