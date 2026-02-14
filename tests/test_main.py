"""
Unit tests for VOO Router Port Forwarding Manager.
"""

import hashlib
import pytest
from unittest.mock import Mock, MagicMock, patch

# Import the module under test
import sys
sys.path.insert(0, '.')
from main import RouterClient, format_rule, create_parser


# Sample test data
SAMPLE_RULES = [
    {
        '__id': '1',
        'Enable': 'true',
        'AllInterfaces': 'true',
        'ExternalPort': '443',
        'ExternalPortEndRange': '443',
        'InternalPort': '443',
        'InternalPortEndRange': '443',
        'Protocol': 'TCP',
        'InternalClient': '192.168.0.66',
        'Description': 'None'
    },
    {
        '__id': '2',
        'Enable': 'false',
        'AllInterfaces': 'true',
        'ExternalPort': '51820',
        'ExternalPortEndRange': '51820',
        'InternalPort': '51820',
        'InternalPortEndRange': '51820',
        'Protocol': 'BOTH',
        'InternalClient': '192.168.0.214',
        'Description': 'VPN'
    },
    {
        '__id': '3',
        'Enable': 'true',
        'AllInterfaces': 'true',
        'ExternalPort': '80',
        'ExternalPortEndRange': '80',
        'InternalPort': '8080',
        'InternalPortEndRange': '8080',
        'Protocol': 'TCP',
        'InternalClient': '192.168.0.100',
        'Description': 'None'
    },
]


class TestFormatRule:
    """Tests for the format_rule function."""
    
    def test_format_enabled_rule(self):
        """Test formatting an enabled rule."""
        rule = SAMPLE_RULES[0]
        result = format_rule(rule)
        assert '[✓]' in result
        assert '443' in result
        assert '192.168.0.66' in result
        assert 'TCP' in result
    
    def test_format_disabled_rule(self):
        """Test formatting a disabled rule."""
        rule = SAMPLE_RULES[1]
        result = format_rule(rule)
        assert '[✗]' in result
        assert '51820' in result
        assert 'BOTH' in result
    
    def test_format_rule_with_description(self):
        """Test formatting a rule with a description."""
        rule = SAMPLE_RULES[1]
        result = format_rule(rule)
        assert '(VPN)' in result
    
    def test_format_rule_without_description(self):
        """Test formatting a rule without description (None)."""
        rule = SAMPLE_RULES[0]
        result = format_rule(rule)
        # Should not contain (None) in output
        assert '(None)' not in result
    
    def test_format_rule_with_port_range(self):
        """Test formatting a rule with a port range."""
        rule = {
            '__id': '1',
            'Enable': 'true',
            'ExternalPort': '8000',
            'ExternalPortEndRange': '8010',
            'InternalPort': '8000',
            'InternalPortEndRange': '8010',
            'Protocol': 'TCP',
            'InternalClient': '192.168.0.1',
            'Description': 'None'
        }
        result = format_rule(rule)
        assert '8000-8010' in result


class TestRouterClient:
    """Tests for the RouterClient class."""
    
    @pytest.fixture
    def mock_session(self):
        """Create a mock session with cookies."""
        session = MagicMock()
        session.cookies.get.return_value = 'test_auth_token'
        return session
    
    @pytest.fixture
    def client(self, mock_session):
        """Create a RouterClient with mocked session."""
        client = RouterClient('192.168.0.1', 'testuser', 'testpass')
        client.session = mock_session
        return client
    
    def test_init(self):
        """Test RouterClient initialization."""
        client = RouterClient('192.168.0.1', 'user', 'pass')
        assert client.router_ip == '192.168.0.1'
        assert client.username == 'user'
        assert client.password == 'pass'
    
    def test_get_portforwarding_rules(self, client, mock_session):
        """Test getting port forwarding rules."""
        mock_response = Mock()
        mock_response.json.return_value = {
            'error': 'ok',
            'data': {'portmappingTbl': SAMPLE_RULES}
        }
        mock_session.get.return_value = mock_response
        
        rules = client.get_portforwarding_rules()
        
        assert len(rules) == 3
        assert rules[0]['ExternalPort'] == '443'
        mock_session.get.assert_called_once()
    
    def test_get_portforwarding_rules_alternative_format(self, client, mock_session):
        """Test getting rules when API returns different format."""
        mock_response = Mock()
        mock_response.json.return_value = {
            'error': 'ok',
            'portmappingTbl': SAMPLE_RULES
        }
        mock_session.get.return_value = mock_response
        
        rules = client.get_portforwarding_rules()
        
        assert len(rules) == 3
    
    def test_get_rule_by_port_found(self, client, mock_session):
        """Test getting a specific rule by port."""
        mock_response = Mock()
        mock_response.json.return_value = {'data': {'portmappingTbl': SAMPLE_RULES}}
        mock_session.get.return_value = mock_response
        
        rule = client.get_rule_by_port(443)
        
        assert rule is not None
        assert rule['ExternalPort'] == '443'
        assert rule['InternalClient'] == '192.168.0.66'
    
    def test_get_rule_by_port_not_found(self, client, mock_session):
        """Test getting a non-existent rule."""
        mock_response = Mock()
        mock_response.json.return_value = {'data': {'portmappingTbl': SAMPLE_RULES}}
        mock_session.get.return_value = mock_response
        
        rule = client.get_rule_by_port(9999)
        
        assert rule is None
    
    def test_set_port_rule_enable(self, client, mock_session):
        """Test enabling a port rule."""
        # Mock get response
        get_response = Mock()
        get_response.json.return_value = {'data': {'portmappingTbl': SAMPLE_RULES}}
        
        # Mock post response
        post_response = Mock()
        post_response.json.return_value = {'error': 'ok'}
        post_response.text = '{"error": "ok"}'
        
        mock_session.get.return_value = get_response
        mock_session.post.return_value = post_response
        
        result = client.set_port_rule(51820, True)
        
        assert result['error'] == 'ok'
        mock_session.post.assert_called_once()
        
        # Check that the post data contains the enabled flag
        call_kwargs = mock_session.post.call_args
        post_data = call_kwargs.kwargs.get('data', call_kwargs[1].get('data', {}))
        assert post_data['portmappingTbl[1][Enable]'] == 'true'
    
    def test_set_port_rule_disable(self, client, mock_session):
        """Test disabling a port rule."""
        get_response = Mock()
        get_response.json.return_value = {'data': {'portmappingTbl': SAMPLE_RULES}}
        
        post_response = Mock()
        post_response.json.return_value = {'error': 'ok'}
        post_response.text = '{"error": "ok"}'
        
        mock_session.get.return_value = get_response
        mock_session.post.return_value = post_response
        
        result = client.set_port_rule(443, False)
        
        assert result['error'] == 'ok'
        call_kwargs = mock_session.post.call_args
        post_data = call_kwargs.kwargs.get('data', call_kwargs[1].get('data', {}))
        assert post_data['portmappingTbl[0][Enable]'] == 'false'
    
    def test_set_port_rule_not_found(self, client, mock_session):
        """Test setting a non-existent port rule raises error."""
        get_response = Mock()
        get_response.json.return_value = {'data': {'portmappingTbl': SAMPLE_RULES}}
        mock_session.get.return_value = get_response
        
        with pytest.raises(ValueError) as exc_info:
            client.set_port_rule(9999, True)
        
        assert 'No port forwarding rule found for port 9999' in str(exc_info.value)
    
    def test_toggle_port_rule_enable(self, client, mock_session):
        """Test toggling a disabled rule to enabled."""
        get_response = Mock()
        get_response.json.return_value = {'data': {'portmappingTbl': SAMPLE_RULES}}
        
        post_response = Mock()
        post_response.json.return_value = {'error': 'ok'}
        post_response.text = '{"error": "ok"}'
        
        mock_session.get.return_value = get_response
        mock_session.post.return_value = post_response
        
        # Port 51820 is disabled in SAMPLE_RULES
        new_state = client.toggle_port_rule(51820)
        
        assert new_state is True
    
    def test_toggle_port_rule_disable(self, client, mock_session):
        """Test toggling an enabled rule to disabled."""
        get_response = Mock()
        get_response.json.return_value = {'data': {'portmappingTbl': SAMPLE_RULES}}
        
        post_response = Mock()
        post_response.json.return_value = {'error': 'ok'}
        post_response.text = '{"error": "ok"}'
        
        mock_session.get.return_value = get_response
        mock_session.post.return_value = post_response
        
        # Port 443 is enabled in SAMPLE_RULES
        new_state = client.toggle_port_rule(443)
        
        assert new_state is False
    
    def test_toggle_port_rule_not_found(self, client, mock_session):
        """Test toggling a non-existent rule raises error."""
        get_response = Mock()
        get_response.json.return_value = {'data': {'portmappingTbl': SAMPLE_RULES}}
        mock_session.get.return_value = get_response
        
        with pytest.raises(ValueError) as exc_info:
            client.toggle_port_rule(9999)
        
        assert 'No port forwarding rule found for port 9999' in str(exc_info.value)


class TestLoginHashing:
    """Tests for the password hashing mechanism."""
    
    def test_pbkdf2_hash(self):
        """Test that PBKDF2 hashing works correctly."""
        password = "testpassword"
        salt = "testsalt"
        
        derived = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 1000, dklen=16)
        result = derived.hex()
        
        # Should be 32 hex characters (16 bytes)
        assert len(result) == 32
        assert all(c in '0123456789abcdef' for c in result)
    
    def test_double_pbkdf2_consistent(self):
        """Test that double PBKDF2 produces consistent results."""
        password = "mypassword"
        salt1 = "salt1"
        salt2 = "salt2"
        
        # First hash
        derived1 = hashlib.pbkdf2_hmac('sha256', password.encode(), salt1.encode(), 1000, dklen=16)
        hashed1 = derived1.hex()
        
        # Second hash
        derived2 = hashlib.pbkdf2_hmac('sha256', hashed1.encode(), salt2.encode(), 1000, dklen=16)
        final = derived2.hex()
        
        # Run again to verify consistency
        derived1_again = hashlib.pbkdf2_hmac('sha256', password.encode(), salt1.encode(), 1000, dklen=16)
        hashed1_again = derived1_again.hex()
        derived2_again = hashlib.pbkdf2_hmac('sha256', hashed1_again.encode(), salt2.encode(), 1000, dklen=16)
        final_again = derived2_again.hex()
        
        assert final == final_again


class TestCreateParser:
    """Tests for the argument parser."""
    
    def test_parser_created(self):
        """Test that parser is created successfully."""
        parser = create_parser()
        assert parser is not None
    
    def test_list_command(self):
        """Test list command parsing."""
        parser = create_parser()
        args = parser.parse_args(['list'])
        assert args.command == 'list'
    
    def test_list_command_with_json(self):
        """Test list command with --json flag."""
        parser = create_parser()
        args = parser.parse_args(['list', '--json'])
        assert args.command == 'list'
        assert args.json is True
    
    def test_show_command(self):
        """Test show command parsing."""
        parser = create_parser()
        args = parser.parse_args(['show', '443'])
        assert args.command == 'show'
        assert args.port == 443
    
    def test_enable_command(self):
        """Test enable command parsing."""
        parser = create_parser()
        args = parser.parse_args(['enable', '51820'])
        assert args.command == 'enable'
        assert args.port == 51820
    
    def test_disable_command(self):
        """Test disable command parsing."""
        parser = create_parser()
        args = parser.parse_args(['disable', '80'])
        assert args.command == 'disable'
        assert args.port == 80
    
    def test_toggle_command(self):
        """Test toggle command parsing."""
        parser = create_parser()
        args = parser.parse_args(['toggle', '443'])
        assert args.command == 'toggle'
        assert args.port == 443
    
    def test_global_options(self):
        """Test global options are parsed."""
        parser = create_parser()
        args = parser.parse_args(['--router-ip', '10.0.0.1', '--user', 'admin', 'list'])
        assert args.router_ip == '10.0.0.1'
        assert args.user == 'admin'
        assert args.command == 'list'
