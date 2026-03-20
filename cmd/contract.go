package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/protobuffalo/go-octra/internal/rpc"
	octx "github.com/protobuffalo/go-octra/internal/tx"
)

var contractCmd = &cobra.Command{
	Use:   "contract",
	Short: "Smart contract commands",
}

var contractCompileCmd = &cobra.Command{
	Use:   "compile",
	Short: "Compile assembly bytecode",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		source, _ := cmd.Flags().GetString("source")
		file, _ := cmd.Flags().GetString("file")
		if source == "" && file != "" {
			data, err := os.ReadFile(file)
			if err != nil {
				fmt.Printf("Error reading file: %s\n", err)
				return
			}
			source = string(data)
		}
		if source == "" {
			fmt.Println("Error: --source or --file required")
			return
		}

		r := s.RPC.CompileAssembly(source)
		if !r.OK {
			fmt.Printf("Error: %s\n", r.Error)
			return
		}
		m := r.Map()
		j, _ := json.MarshalIndent(map[string]interface{}{
			"bytecode":     rpc.MapString(m, "bytecode", ""),
			"size":         rpc.MapInt(m, "size", 0),
			"instructions": rpc.MapInt(m, "instructions", 0),
		}, "", "  ")
		fmt.Println(string(j))
	},
}

var contractCompileAmlCmd = &cobra.Command{
	Use:   "compile-aml",
	Short: "Compile AML source code",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		source, _ := cmd.Flags().GetString("source")
		file, _ := cmd.Flags().GetString("file")
		if source == "" && file != "" {
			data, err := os.ReadFile(file)
			if err != nil {
				fmt.Printf("Error reading file: %s\n", err)
				return
			}
			source = string(data)
		}
		if source == "" {
			fmt.Println("Error: --source or --file required")
			return
		}

		r := s.RPC.CompileAml(source)
		if !r.OK {
			fmt.Printf("Error: %s\n", r.Error)
			return
		}
		m := r.Map()
		result := map[string]interface{}{
			"bytecode":     rpc.MapString(m, "bytecode", ""),
			"size":         rpc.MapInt(m, "size", 0),
			"instructions": rpc.MapInt(m, "instructions", 0),
			"version":      rpc.MapString(m, "version", ""),
		}
		if abi, ok := m["abi"]; ok {
			result["abi"] = abi
		}
		j, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(j))
	},
}

var contractAddressCmd = &cobra.Command{
	Use:   "address",
	Short: "Compute contract address",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		bytecode, _ := cmd.Flags().GetString("bytecode")
		if bytecode == "" {
			fmt.Println("Error: --bytecode required")
			return
		}

		bi := octx.GetNonceBalance(s.RPC, s.Wallet)
		r := s.RPC.ComputeContractAddress(bytecode, s.Wallet.Addr, bi.Nonce+1)
		if !r.OK {
			fmt.Printf("Error: %s\n", r.Error)
			return
		}
		m := r.Map()
		j, _ := json.MarshalIndent(map[string]interface{}{
			"address":  rpc.MapString(m, "address", ""),
			"deployer": rpc.MapString(m, "deployer", ""),
			"nonce":    rpc.MapInt(m, "nonce", 0),
		}, "", "  ")
		fmt.Println(string(j))
	},
}

var contractDeployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Deploy a smart contract",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		bytecode, _ := cmd.Flags().GetString("bytecode")
		params, _ := cmd.Flags().GetString("params")
		ou, _ := cmd.Flags().GetString("ou")
		if bytecode == "" {
			fmt.Println("Error: --bytecode required")
			return
		}
		if ou == "" {
			ou = "50000000"
		}

		bi := octx.GetNonceBalance(s.RPC, s.Wallet)
		ar := s.RPC.ComputeContractAddress(bytecode, s.Wallet.Addr, bi.Nonce+1)
		if !ar.OK {
			fmt.Printf("Error: %s\n", ar.Error)
			return
		}
		m := ar.Map()
		contractAddr := rpc.MapString(m, "address", "")

		tx := &octx.Transaction{
			From:          s.Wallet.Addr,
			To:            contractAddr,
			Amount:        "0",
			Nonce:         bi.Nonce + 1,
			OU:            ou,
			Timestamp:     octx.NowTS(),
			OpType:        "deploy",
			EncryptedData: bytecode,
			Message:       params,
		}
		octx.SignTx(tx, s.Wallet.SK, s.Wallet.PubB64)
		txHash, err := octx.SubmitTx(s.RPC, tx)
		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return
		}
		fmt.Printf("Contract deployed: %s\n", contractAddr)
		fmt.Printf("Transaction: %s\n", txHash)
	},
}

var contractVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify contract source",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		addr, _ := cmd.Flags().GetString("address")
		source, _ := cmd.Flags().GetString("source")
		file, _ := cmd.Flags().GetString("file")
		if source == "" && file != "" {
			data, err := os.ReadFile(file)
			if err != nil {
				fmt.Printf("Error: %s\n", err)
				return
			}
			source = string(data)
		}
		if addr == "" || source == "" {
			fmt.Println("Error: --address and (--source or --file) required")
			return
		}

		r := s.RPC.ContractVerify(addr, source)
		if !r.OK {
			fmt.Printf("Verification failed: %s\n", r.Error)
			return
		}
		fmt.Println("Verification passed")
		var raw json.RawMessage
		r.Unmarshal(&raw)
		fmt.Println(string(raw))
	},
}

var contractCallCmd = &cobra.Command{
	Use:   "call",
	Short: "Call a contract method (state-changing)",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		addr, _ := cmd.Flags().GetString("address")
		method, _ := cmd.Flags().GetString("method")
		params, _ := cmd.Flags().GetString("params")
		amount, _ := cmd.Flags().GetString("amount")
		ou, _ := cmd.Flags().GetString("ou")

		if addr == "" || method == "" {
			fmt.Println("Error: --address and --method required")
			return
		}
		if amount == "" {
			amount = "0"
		}
		if ou == "" {
			ou = "1000"
		}
		if params == "" {
			params = "[]"
		}

		bi := octx.GetNonceBalance(s.RPC, s.Wallet)
		tx := &octx.Transaction{
			From:          s.Wallet.Addr,
			To:            addr,
			Amount:        amount,
			Nonce:         bi.Nonce + 1,
			OU:            ou,
			Timestamp:     octx.NowTS(),
			OpType:        "call",
			EncryptedData: method,
			Message:       params,
		}
		octx.SignTx(tx, s.Wallet.SK, s.Wallet.PubB64)
		txHash, err := octx.SubmitTx(s.RPC, tx)
		if err != nil {
			fmt.Printf("Error: %s\n", err)
			return
		}
		fmt.Printf("Transaction: %s\n", txHash)
	},
}

var contractViewCmd = &cobra.Command{
	Use:   "view",
	Short: "Call a contract method (read-only)",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		addr, _ := cmd.Flags().GetString("address")
		method, _ := cmd.Flags().GetString("method")
		params, _ := cmd.Flags().GetString("params")

		if addr == "" || method == "" {
			fmt.Println("Error: --address and --method required")
			return
		}

		var parsedParams interface{}
		if params != "" {
			json.Unmarshal([]byte(params), &parsedParams)
		}
		if parsedParams == nil {
			parsedParams = []interface{}{}
		}

		r := s.RPC.ContractCallView(addr, method, parsedParams, s.Wallet.Addr)
		if !r.OK {
			fmt.Printf("Error: %s\n", r.Error)
			return
		}
		fmt.Println(string(r.Data))
	},
}

var contractInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Get contract info",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		addr, _ := cmd.Flags().GetString("address")
		if addr == "" {
			fmt.Println("Error: --address required")
			return
		}

		r := s.RPC.VMContract(addr)
		if !r.OK {
			fmt.Printf("Error: %s\n", r.Error)
			return
		}
		fmt.Println(string(r.Data))
	},
}

var contractReceiptCmd = &cobra.Command{
	Use:   "receipt",
	Short: "Get contract execution receipt",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		hash, _ := cmd.Flags().GetString("hash")
		if hash == "" && len(args) > 0 {
			hash = args[0]
		}
		if hash == "" {
			fmt.Println("Error: --hash required")
			return
		}

		r := s.RPC.ContractReceipt(hash)
		if !r.OK {
			fmt.Printf("Error: %s\n", r.Error)
			return
		}
		fmt.Println(string(r.Data))
	},
}

var contractStorageCmd = &cobra.Command{
	Use:   "storage",
	Short: "Read contract storage by key",
	Run: func(cmd *cobra.Command, args []string) {
		s := mustSession(cmd)
		defer s.Close()

		addr, _ := cmd.Flags().GetString("address")
		key, _ := cmd.Flags().GetString("key")
		if addr == "" || key == "" {
			fmt.Println("Error: --address and --key required")
			return
		}

		r := s.RPC.ContractStorage(addr, key)
		if !r.OK {
			fmt.Printf("Error: %s\n", r.Error)
			return
		}
		m := r.Map()
		if v, ok := m["value"]; ok && v != nil {
			fmt.Printf("%v\n", v)
		} else {
			fmt.Println("null")
		}
	},
}

func init() {
	contractCmd.AddCommand(contractCompileCmd)
	contractCmd.AddCommand(contractCompileAmlCmd)
	contractCmd.AddCommand(contractAddressCmd)
	contractCmd.AddCommand(contractDeployCmd)
	contractCmd.AddCommand(contractVerifyCmd)
	contractCmd.AddCommand(contractCallCmd)
	contractCmd.AddCommand(contractViewCmd)
	contractCmd.AddCommand(contractInfoCmd)
	contractCmd.AddCommand(contractReceiptCmd)
	contractCmd.AddCommand(contractStorageCmd)

	for _, c := range []*cobra.Command{
		contractCompileCmd, contractCompileAmlCmd, contractAddressCmd,
		contractDeployCmd, contractVerifyCmd, contractCallCmd,
		contractViewCmd, contractInfoCmd, contractReceiptCmd, contractStorageCmd,
	} {
		c.Flags().String("account", "", "Account address")
	}

	contractCompileCmd.Flags().String("source", "", "Assembly source")
	contractCompileCmd.Flags().String("file", "", "Source file path")

	contractCompileAmlCmd.Flags().String("source", "", "AML source")
	contractCompileAmlCmd.Flags().String("file", "", "Source file path")

	contractAddressCmd.Flags().String("bytecode", "", "Bytecode (base64)")

	contractDeployCmd.Flags().String("bytecode", "", "Bytecode (base64)")
	contractDeployCmd.Flags().String("params", "", "Constructor params")
	contractDeployCmd.Flags().String("ou", "", "Operation units")
	contractDeployCmd.MarkFlagRequired("bytecode")

	contractVerifyCmd.Flags().String("address", "", "Contract address")
	contractVerifyCmd.Flags().String("source", "", "Source code")
	contractVerifyCmd.Flags().String("file", "", "Source file path")

	contractCallCmd.Flags().String("address", "", "Contract address")
	contractCallCmd.Flags().String("method", "", "Method name")
	contractCallCmd.Flags().String("params", "", "JSON params array")
	contractCallCmd.Flags().String("amount", "0", "Amount to send")
	contractCallCmd.Flags().String("ou", "", "Operation units")

	contractViewCmd.Flags().String("address", "", "Contract address")
	contractViewCmd.Flags().String("method", "", "Method name")
	contractViewCmd.Flags().String("params", "", "JSON params array")

	contractInfoCmd.Flags().String("address", "", "Contract address")

	contractReceiptCmd.Flags().String("hash", "", "Transaction hash")

	contractStorageCmd.Flags().String("address", "", "Contract address")
	contractStorageCmd.Flags().String("key", "", "Storage key")

	_ = strconv.Itoa // suppress import
}
