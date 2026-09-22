"""
Unit tests for AgentShield Identity Verifier.
"""
import pytest
import jwt
from datetime import datetime, timedelta

from agentshield.identity.verifier import IdentityVerifier
from agentshield.core.models import Principal
from agentshield.core.exceptions import IdentityVerificationError


class TestIdentityVerifier:
    """Test JWT-based identity verification."""
    
    @pytest.fixture
    def verifier(self):
        """Create verifier with test secret."""
        return IdentityVerifier(secret_key="test_secret_key_123")
    
    @pytest.fixture
    def valid_token(self, verifier):
        """Generate a valid test token."""
        payload = {
            "user_id": "user_123",  # Use user_id not sub
            "agent_id": "finance-agent-v1",
            "roles": ["employee", "analyst"],
            "exp": datetime.utcnow() + timedelta(hours=1),
            "iat": datetime.utcnow()
        }
        return jwt.encode(payload, verifier.secret_key, algorithm="HS256")
    
    def test_verify_valid_token(self, verifier, valid_token):
        """Should verify valid token and return Principal."""
        principal = verifier.verify_token(valid_token)
        
        assert isinstance(principal, Principal)
        assert principal.user_id == "user_123"
        assert principal.agent_id == "finance-agent-v1"
        assert "employee" in principal.roles
    
    def test_verify_expired_token_raises(self, verifier):
        """Expired token should raise IdentityVerificationError."""
        payload = {
            "user_id": "user_123",
            "agent_id": "agent-1",
            "roles": [],
            "exp": datetime.utcnow() - timedelta(hours=1),  # Expired
            "iat": datetime.utcnow() - timedelta(hours=2)
        }
        expired_token = jwt.encode(payload, verifier.secret_key, algorithm="HS256")
        
        with pytest.raises(IdentityVerificationError):
            verifier.verify_token(expired_token)
    
    def test_verify_invalid_signature_raises(self, verifier):
        """Token with wrong signature should raise error."""
        payload = {
            "user_id": "user_123",
            "agent_id": "agent-1",
            "roles": [],
            "exp": datetime.utcnow() + timedelta(hours=1)
        }
        # Encode with different secret
        bad_token = jwt.encode(payload, "wrong_secret", algorithm="HS256")
        
        with pytest.raises(IdentityVerificationError):
            verifier.verify_token(bad_token)
    
    def test_verify_missing_user_id_raises(self, verifier):
        """Token missing user_id (sub) should raise error."""
        payload = {
            "agent_id": "agent-1",  # Missing 'sub'
            "roles": [],
            "exp": datetime.utcnow() + timedelta(hours=1)
        }
        token = jwt.encode(payload, verifier.secret_key, algorithm="HS256")
        
        with pytest.raises(IdentityVerificationError):
            verifier.verify_token(token)
    
    def test_verify_missing_agent_id_raises(self, verifier):
        """Token missing agent_id should raise error."""
        payload = {
            "user_id": "user_123",
            # Missing 'agent_id'
            "roles": [],
            "exp": datetime.utcnow() + timedelta(hours=1)
        }
        token = jwt.encode(payload, verifier.secret_key, algorithm="HS256")
        
        with pytest.raises(IdentityVerificationError):
            verifier.verify_token(token)
    
    def test_verify_malformed_token_raises(self, verifier):
        """Malformed token should raise error."""
        with pytest.raises(IdentityVerificationError):
            verifier.verify_token("not.a.valid.jwt.token")
    
    def test_principal_does_not_contain_raw_token(self, verifier, valid_token):
        """Principal should not contain the raw token."""
        principal = verifier.verify_token(valid_token)
        
        # Check that no token field exists
        assert not hasattr(principal, 'token')
        assert not hasattr(principal, 'raw_token')
        assert 'token' not in str(principal)
    
    def test_auth_context_contains_metadata(self, verifier, valid_token):
        """Auth context should contain verification metadata."""
        principal = verifier.verify_token(valid_token)
        
        assert 'auth_method' in principal.auth_context
        assert principal.auth_context['auth_method'] == 'jwt'
