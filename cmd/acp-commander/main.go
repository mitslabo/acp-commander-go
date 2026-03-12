package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
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

func run(args []string) error {
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
	openBox := hasParam(args, "-o")
	findLS := hasParam(args, "-f")
	needAuth := (openBox || cmdline != "") && !hasParam(args, "-na")
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
