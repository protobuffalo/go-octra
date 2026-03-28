package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/protobuffalo/go-octra/internal/config"
	"github.com/protobuffalo/go-octra/internal/session"
	"github.com/protobuffalo/go-octra/internal/wallet"
)

func Execute() {
	// Load global config and apply to packages
	cfg := config.Load()
	wallet.ApplyConfig(cfg)

	args := os.Args[1:]
	if len(args) == 0 {
		printHelp()
		return
	}

	switch args[0] {
	case "wallet":
		dispatchWallet(args[1:])
	case "balance":
		runBalance(args[1:])
	case "history":
		runHistory(args[1:])
	case "fee":
		runFee(args[1:])
	case "send":
		runSend(args[1:])
	case "tx":
		runTx(args[1:])
	case "keys":
		dispatchKeys(args[1:])
	case "fhe":
		dispatchFhe(args[1:])
	case "stealth":
		dispatchStealth(args[1:])
	case "contract":
		dispatchContract(args[1:])
	case "token":
		dispatchToken(args[1:])
	case "config":
		dispatchConfig(args[1:])
	case "keyswitch":
		runKeyswitch(args[1:])
	case "help", "--help", "-h":
		printHelp()
	default:
		fmt.Printf("Unknown command: %s\n", args[0])
		printHelp()
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println("Octra Wallet CLI")
	fmt.Println()
	fmt.Println("Usage: octra <command> [subcommand] [flags]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  wallet      Wallet management commands")
	fmt.Println("  balance     Show wallet balance")
	fmt.Println("  send        Send OCT to an address")
	fmt.Println("  history     Show transaction history")
	fmt.Println("  fee         Show recommended fees")
	fmt.Println("  tx          Get transaction details")
	fmt.Println("  keys        Key management commands")
	fmt.Println("  fhe         FHE encrypt/decrypt balance operations")
	fmt.Println("  stealth     Stealth transfer commands")
	fmt.Println("  contract    Smart contract commands")
	fmt.Println("  token       Token commands")
	fmt.Println("  config      Configuration commands")
	fmt.Println("  keyswitch   Reset encryption key (resolve PVAC key mismatch)")
}

func readPin(prompt string) string {
	if pin := os.Getenv("OCTRA_PIN"); pin != "" {
		return pin
	}
	fmt.Print(prompt)
	b, err := readPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readPassword(fd int) ([]byte, error) {
	var old syscall.Termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&old))); errno != 0 {
		// Not a terminal — read normally (piped input)
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil && len(line) == 0 {
			return nil, err
		}
		return []byte(strings.TrimRight(line, "\r\n")), nil
	}

	newState := old
	newState.Lflag &^= syscall.ECHO
	syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&newState)))
	defer syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&old)))

	var buf [256]byte
	n, err := syscall.Read(fd, buf[:])
	if err != nil {
		return nil, err
	}
	if n > 0 && buf[n-1] == '\n' {
		n--
	}
	if n > 0 && buf[n-1] == '\r' {
		n--
	}
	return buf[:n], nil
}

func validatePin(pin string) bool {
	if len(pin) != 6 {
		return false
	}
	for _, c := range pin {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func loadSession(pin string) (*session.Session, error) {
	entries := wallet.LoadManifest()
	if len(entries) == 0 {
		if wallet.HasEncryptedWallet() {
			return session.Load(wallet.WalletFile, pin)
		}
		return nil, fmt.Errorf("no wallet found. Use 'octra wallet create' first")
	}
	return session.Load(entries[0].File, pin)
}

func loadSessionForAddr(addr, pin string) (*session.Session, error) {
	entries := wallet.LoadManifest()
	for _, e := range entries {
		if e.Addr == addr {
			return session.Load(e.File, pin)
		}
	}
	return nil, fmt.Errorf("account %s not found in manifest", addr)
}

func mustSession(account string) *session.Session {
	pin := readPin("Enter PIN: ")
	if !validatePin(pin) {
		fmt.Println("Error: PIN must be exactly 6 digits")
		os.Exit(1)
	}
	var s *session.Session
	var err error
	if account != "" {
		s, err = loadSessionForAddr(account, pin)
	} else {
		s, err = loadSession(pin)
	}
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}
	return s
}
