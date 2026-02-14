#!/usr/bin/env python3
"""
VOO Router Port Forwarding Manager

A CLI tool to manage port forwarding rules on VOO/Technicolor routers.
"""

import argparse
import os
import sys
import requests
import hashlib
from dotenv import load_dotenv

load_dotenv()

ROUTER_IP = os.getenv("ROUTER_IP", "192.168.0.1")
USERNAME = os.getenv("ROUTER_USER")
PASSWORD = os.getenv("ROUTER_PASS")


class RouterClient:
    def __init__(self, router_ip, username, password):
        self.router_ip = router_ip
        self.username = username
        self.password = password
        self.session = requests.Session()
        
    def login_to_router(self):
        session = self.session
        
        # Step 1: Request salt
        salt_response = session.post(
            f"http://{self.router_ip}/api/v1/session/login",
            data={
                "username": self.username,
                "password": "seeksalthash"
            }
        )
        
        # Extract salt from response
        salt_data = salt_response.json()
        salt = salt_data.get('salt', '')
        saltwebui = salt_data.get('saltwebui', '')
        
        # Double PBKDF2 hashing (as done by SJCL in the router's JS)
        # Step 1: PBKDF2(password, salt) - 1000 iterations, 128 bits (16 bytes)
        derived1 = hashlib.pbkdf2_hmac('sha256', self.password.encode(), salt.encode(), 1000, dklen=16)
        hashed1 = derived1.hex()
        
        # Step 2: PBKDF2(hashed1, saltwebui) - 1000 iterations, 128 bits (16 bytes)
        derived2 = hashlib.pbkdf2_hmac('sha256', hashed1.encode(), saltwebui.encode(), 1000, dklen=16)
        hashed_password = derived2.hex()
        
        login_response = session.post(
            f"http://{self.router_ip}/api/v1/session/login",
            data={
                "username": self.username,
                "password": hashed_password
            }
        )
        
        if login_response.json().get('error') != 'ok':
            raise Exception(f"Login failed: {login_response.text}")
        
        # Initialize session by calling menu endpoint (as the browser does after login)
        auth_cookie = session.cookies.get('auth')
        headers = {
            'X-CSRF-TOKEN': auth_cookie,
            'X-Requested-With': 'XMLHttpRequest'
        }
        session.get(
            f"http://{self.router_ip}/api/v1/session/menu",
            headers=headers
        )
        
        self.session = session


    def get_portforwarding_rules(self):
        """
        Get the current port forwarding rules from the router.
        
        Returns a list of port forwarding rule dictionaries.
        """
        # Get CSRF token from cookies
        auth_cookie = self.session.cookies.get('auth')
        
        headers = {
            'X-CSRF-TOKEN': auth_cookie,
            'X-Requested-With': 'XMLHttpRequest'
        }
        
        response = self.session.get(
            f"http://{self.router_ip}/api/v1/portforward",
            headers=headers
        )
        
        data = response.json()
        return data.get('data', {}).get('portmappingTbl', data.get('portmappingTbl', []))

    def set_port_rule(self, port: int, enabled: bool) -> dict:
        """
        Enable or disable a port forwarding rule.
        
        :param port: The external port number to modify
        :param enabled: True to enable, False to disable the rule
        :return: API response
        """
        rules = self.get_portforwarding_rules()
        
        # Check if rule exists
        port_str = str(port)
        rule_exists = any(str(rule.get('ExternalPort')) == port_str for rule in rules)
        if not rule_exists:
            raise ValueError(f"No port forwarding rule found for port {port}")
        
        # Get CSRF token from cookies
        auth_cookie = self.session.cookies.get('auth')
        
        headers = {
            'X-CSRF-TOKEN': auth_cookie,
            'X-Requested-With': 'XMLHttpRequest'
        }
        
        # Build the form data
        data = {
            'pwEnable': 'true',
            'hsPwEnable': 'true'
        }
        
        # Add all rules to the form data
        for i, rule in enumerate(rules):
            rule_enabled = rule.get('Enable', 'true')
            if str(rule.get('ExternalPort')) == port_str:
                rule_enabled = 'true' if enabled else 'false'
            
            prefix = f'portmappingTbl[{i}]'
            data[f'{prefix}[__id]'] = rule.get('__id', i + 1)
            data[f'{prefix}[Enable]'] = rule_enabled
            data[f'{prefix}[ExternalPort]'] = rule.get('ExternalPort')
            data[f'{prefix}[ExternalPortEndRange]'] = rule.get('ExternalPortEndRange')
            data[f'{prefix}[InternalPort]'] = rule.get('InternalPort')
            data[f'{prefix}[InternalPortEndRange]'] = rule.get('InternalPortEndRange')
            data[f'{prefix}[Protocol]'] = rule.get('Protocol')
            data[f'{prefix}[InternalClient]'] = rule.get('InternalClient')
            data[f'{prefix}[AllInterfaces]'] = rule.get('AllInterfaces', 'true')
            data[f'{prefix}[Description]'] = rule.get('Description', 'None')
        
        response = self.session.post(
            f"http://{self.router_ip}/api/v1/portforward",
            data=data,
            headers=headers
        )
        
        return response.json() if response.text else {'status': response.status_code}

    def toggle_port_rule(self, port: int) -> bool:
        """
        Toggle a port forwarding rule.
        
        :param port: The external port number to toggle
        :return: The new enabled state
        """
        rules = self.get_portforwarding_rules()
        port_str = str(port)
        
        rule = next((r for r in rules if str(r['ExternalPort']) == port_str), None)
        
        if not rule:
            raise ValueError(f"No port forwarding rule found for port {port}")
        
        current_enabled = rule['Enable'] == 'true'
        new_status = not current_enabled
        self.set_port_rule(port, new_status)
        return new_status

    def get_rule_by_port(self, port: int) -> dict | None:
        """
        Get a specific port forwarding rule by port number.
        
        :param port: The external port number
        :return: The rule dict or None if not found
        """
        rules = self.get_portforwarding_rules()
        port_str = str(port)
        return next((r for r in rules if str(r['ExternalPort']) == port_str), None)


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog='voo-router',
        description='Manage port forwarding rules on VOO/Technicolor routers.',
        epilog='Environment variables: ROUTER_IP, ROUTER_USER, ROUTER_PASS (or use .env file)'
    )
    
    parser.add_argument(
        '--router-ip',
        default=ROUTER_IP,
        help=f'Router IP address (default: {ROUTER_IP})'
    )
    parser.add_argument(
        '--user',
        default=USERNAME,
        help='Router username (default: from ROUTER_USER env)'
    )
    parser.add_argument(
        '--password',
        default=PASSWORD,
        help='Router password (default: from ROUTER_PASS env)'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # List command
    list_parser = subparsers.add_parser(
        'list',
        help='List all port forwarding rules'
    )
    list_parser.add_argument(
        '--json',
        action='store_true',
        help='Output in JSON format'
    )
    
    # Show command
    show_parser = subparsers.add_parser(
        'show',
        help='Show details of a specific port forwarding rule'
    )
    show_parser.add_argument(
        'port',
        type=int,
        help='External port number'
    )
    
    # Enable command
    enable_parser = subparsers.add_parser(
        'enable',
        help='Enable a port forwarding rule'
    )
    enable_parser.add_argument(
        'port',
        type=int,
        help='External port number to enable'
    )
    
    # Disable command
    disable_parser = subparsers.add_parser(
        'disable',
        help='Disable a port forwarding rule'
    )
    disable_parser.add_argument(
        'port',
        type=int,
        help='External port number to disable'
    )
    
    # Toggle command
    toggle_parser = subparsers.add_parser(
        'toggle',
        help='Toggle a port forwarding rule'
    )
    toggle_parser.add_argument(
        'port',
        type=int,
        help='External port number to toggle'
    )
    
    return parser


def format_rule(rule: dict, verbose: bool = False) -> str:
    """Format a rule for display."""
    status = '✓' if rule['Enable'] == 'true' else '✗'
    port_range = rule['ExternalPort']
    if rule['ExternalPort'] != rule['ExternalPortEndRange']:
        port_range = f"{rule['ExternalPort']}-{rule['ExternalPortEndRange']}"
    
    internal = f"{rule['InternalClient']}:{rule['InternalPort']}"
    if rule['InternalPort'] != rule['InternalPortEndRange']:
        internal = f"{rule['InternalClient']}:{rule['InternalPort']}-{rule['InternalPortEndRange']}"
    
    desc = rule.get('Description', 'None')
    if desc == 'None':
        desc = ''
    else:
        desc = f" ({desc})"
    
    return f"[{status}] {port_range:>5} -> {internal:<22} {rule['Protocol']:<4}{desc}"


def main():
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
    
    # Validate credentials
    if not args.user or not args.password:
        print("Error: Router credentials not provided.", file=sys.stderr)
        print("Set ROUTER_USER and ROUTER_PASS environment variables or use --user/--password", file=sys.stderr)
        sys.exit(1)
    
    # Connect to router
    try:
        router = RouterClient(args.router_ip, args.user, args.password)
        router.login_to_router()
    except Exception as e:
        print(f"Error connecting to router: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Execute command
    try:
        if args.command == 'list':
            rules = router.get_portforwarding_rules()
            if args.json:
                import json
                print(json.dumps(rules, indent=2))
            else:
                print(f"Port forwarding rules ({len(rules)} total):\n")
                for rule in rules:
                    print(f"  {format_rule(rule)}")
        
        elif args.command == 'show':
            rule = router.get_rule_by_port(args.port)
            if rule:
                print(f"Port {args.port}:")
                for key, value in rule.items():
                    print(f"  {key}: {value}")
            else:
                print(f"No rule found for port {args.port}", file=sys.stderr)
                sys.exit(1)
        
        elif args.command == 'enable':
            rule = router.get_rule_by_port(args.port)
            if not rule:
                print(f"No rule found for port {args.port}", file=sys.stderr)
                sys.exit(1)
            if rule['Enable'] == 'true':
                print(f"Port {args.port} is already enabled")
            else:
                router.set_port_rule(args.port, True)
                print(f"✓ Port {args.port} enabled")
        
        elif args.command == 'disable':
            rule = router.get_rule_by_port(args.port)
            if not rule:
                print(f"No rule found for port {args.port}", file=sys.stderr)
                sys.exit(1)
            if rule['Enable'] == 'false':
                print(f"Port {args.port} is already disabled")
            else:
                router.set_port_rule(args.port, False)
                print(f"✗ Port {args.port} disabled")
        
        elif args.command == 'toggle':
            new_state = router.toggle_port_rule(args.port)
            status = '✓ enabled' if new_state else '✗ disabled'
            print(f"Port {args.port} {status}")
    
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
