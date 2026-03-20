# go-octra

CLI wallet for the Octra blockchain. Built with Go + CGO (embedded C++ PVAC library for FHE operations).

## Build

```
make
```

Requires: Go 1.21+, C++17 compiler, CGO enabled. Hardware AES support required (amd64 or arm64).

## Usage

All commands that access a wallet require a 6-digit PIN. Set `OCTRA_PIN` env var to skip interactive prompt.

```
./octra wallet create              # Create a new wallet
./octra wallet import              # Import from mnemonic or private key
./octra balance                    # Show public + encrypted balance
./octra send --to <addr> --amount <amt>
./octra history                    # Transaction history
./octra fee                        # Recommended fees
```

### FHE (encrypted balance)

```
./octra fhe encrypt --amount <amt>       # Move funds to encrypted balance
./octra fhe decrypt --amount <amt>       # Move funds to public balance
./octra fhe encrypt-value --value <n>    # Encrypt a raw value (no tx)
./octra fhe decrypt-value --ciphertext <ct>
```

### Stealth transfers

```
./octra stealth send --to <addr> --amount <amt>
./octra stealth scan                     # Scan for incoming stealth transfers
./octra stealth claim --ids <id1,id2>    # Claim stealth outputs
```

### Keys & accounts

```
./octra keys show                  # Show public keys
./octra keys export                # Export private key / mnemonic
./octra wallet accounts            # List accounts
./octra wallet derive              # Derive HD child account
./octra keyswitch                  # Reset PVAC encryption key
```

### Smart contracts

```
./octra contract compile --file <asm>
./octra contract compile-aml --file <aml>
./octra contract deploy --bytecode <hex> --ou <units>
./octra contract call --address <addr> --method <name> --args <json>
./octra contract view --address <addr> --method <name>
./octra contract info --address <addr>
```

### Tokens

```
./octra token list
./octra token transfer --token <addr> --to <addr> --amount <amt>
```

### Config

```
./octra config set --rpc <url>
./octra config change-pin
```

Use `--account <addr>` on any command to target a specific wallet.
