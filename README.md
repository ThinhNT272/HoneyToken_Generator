# Honey Token Generator

A Python tool designed to deploy and clean up deception honey tokens within a Active Directory (AD) environment. It creates decoy user and service accounts in AD, configures Service Principal Names (SPNs) for Kerberoasting decoys, and injects cached credentials onto workstations to detect lateral movement attempts such as Pass-the-Hash.

## Features

- **Decoy Provisioning:** Automatically provisions randomized user and service accounts under a dedicated OU in AD using the LDAP/LDAPS protocol.
- **Kerberoasting Trap:** Assigns specific Service Principal Names (SPNs) to decoy accounts.
- **Pass-the-Hash Trap:** Connects via WinRM to endpoint workstations to inject cached credentials using Windows Credential Manager (`cmdkey`).
- **Orchestration & Cleanup:** Maintains active deployment tracking via `list.json` and offers a clean-up command to remove all traces (accounts, credentials, files) safely.
- **Dry-run Mode:** Allows validation of configuration and simulated deployment/cleanup without making live changes.

## Project Structure

```
Honey_Token_Generator/
├── honey_token_gen.py    # Main entry point (CLI + orchestration)
├── ldap_ops.py           # AD account creation, SPN assignment, cleanup
├── winrm_ops.py          # Cached credential injection/removal
├── config.py             # Config loading and validation logic
├── config.example.json   # Template/Example configuration schema
├── requirements.txt      # Python dependencies
└── README.md             # This documentation
```

## Setup Instructions

### Prerequisites

- Python 3.10 or newer.
- Port `636` (LDAPS) or `389` (LDAP) reachable on the Domain Controller.
- Port `5985` (HTTP) or `5986` (HTTPS) WinRM reachable on Windows endpoints.

### Installation

1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Copy and customize the configuration file:
   ```bash
   cp config.example.json config.json
   ```

## Usage

The Honey Token Generator exposes a CLI interface with `deploy` and `cleanup` commands.

### Deploy Decoys

Deploy decoy accounts to AD and endpoints:
```bash
python honey_token_gen.py deploy --config config.json
```

To test configurations and flow without modifying the server or workstations, run in dry-run mode:
```bash
python honey_token_gen.py deploy --config config.json --dry-run
```

Upon successful execution (non-dry-run), a `list.json` record is generated in the working directory tracking the deployed accounts and which hosts they were mapped to.

### Cleanup Decoys

To tear down all deployed decoys, clean AD, remove endpoint cached credentials, and delete `list.json`:
```bash
python honey_token_gen.py cleanup --config config.json
```

Or run dry-run cleanup:
```bash
python honey_token_gen.py cleanup --config config.json --dry-run
```
