# VOO Router Port Forwarding Manager

A CLI tool to manage port forwarding rules on VOO/Technicolor routers.

## Features

- 📋 **List** all port forwarding rules
- ✅ **Enable/Disable** rules by port number
- 🔄 **Toggle** rules on/off
- 🔐 Secure authentication using PBKDF2 (matches router's web UI)
- 📄 JSON output support for scripting

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/voo_router.git
cd voo_router

# Install dependencies using uv
uv sync
```

## Configuration

Create a `.env` file in the project root:

```bash
cp .env.example .env
```

Edit `.env` with your router credentials:

```env
ROUTER_IP=192.168.0.1
ROUTER_USER=voo
ROUTER_PASS=your_password_here
```

## Usage

```bash
# Show help
uv run main.py --help

# List all port forwarding rules
uv run main.py list

# List rules in JSON format
uv run main.py list --json

# Show details of a specific rule
uv run main.py show 443

# Enable a port forwarding rule
uv run main.py enable 51820

# Disable a port forwarding rule
uv run main.py disable 51820

# Toggle a rule on/off
uv run main.py toggle 51820
```

### Command Line Options

```text
usage: voo-router [-h] [--router-ip ROUTER_IP] [--user USER] [--password PASSWORD]
                  {list,show,enable,disable,toggle} ...

Manage port forwarding rules on VOO/Technicolor routers.

Commands:
  list      List all port forwarding rules
  show      Show details of a specific port forwarding rule
  enable    Enable a port forwarding rule
  disable   Disable a port forwarding rule
  toggle    Toggle a port forwarding rule

Options:
  --router-ip    Router IP address (default: 192.168.0.1)
  --user         Router username
  --password     Router password
```

## Examples

### List all rules

```bash
$ uv run main.py list

Port forwarding rules (7 total):

  [✓]   443 -> 192.168.0.66:443       TCP
  [✓] 25565 -> 192.168.0.90:25565     TCP
  [✗] 51820 -> 192.168.0.214:51820    BOTH
  [✓]    80 -> 192.168.0.66:84        TCP
```

### Toggle VPN rule

```bash
$ uv run main.py toggle 51820
Port 51820 ✓ enabled
```

### Use with different router

```bash
$ uv run main.py --router-ip 192.168.1.1 --user admin --password secret list
```

## Compatibility

Tested with:
- VOO (Belgium) Technicolor routers
- Other Technicolor routers with similar firmware may also work

## How It Works

The tool authenticates with the router using the same double-PBKDF2 hashing algorithm as the web interface:

1. Request a salt from the router
2. Hash the password: `PBKDF2(password, salt, 1000 iterations, 128 bits)`
3. Hash again with web UI salt: `PBKDF2(hash1, saltwebui, 1000 iterations, 128 bits)`
4. Use the session to make authenticated API calls

## License

GPL-2.0