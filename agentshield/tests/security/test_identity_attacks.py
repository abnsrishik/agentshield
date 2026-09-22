"""Security tests: Identity spoofing, JWT tampering, and authentication attacks."""

import pytest
import jwt
from datetime import datetime, timedelta, timezone

from agentshield.core.exceptions import AuthorizationDeniedError
from tests.conftest import create_token, TEST_JWT_SECRET


class TestIdentityAttacksSecurity:
    """Tests verifying cryptographic verification of caller identity."""

    def test_missing_auth_token_blocked(self, shield):
        """Action with empty or None auth token must be blocked immediately."""
        with pytest.raises(AuthorizationDeniedError, match="Invalid or missing authentication"):
            shield.execute(
                action="transfer_money",
                params={"amount": 100, "recipient": "Bob", "account_number": "1234567890"},
                auth_token=""
            )

    def test_malformed_token_blocked(self, shield):
        """Malformed, non-JWT token string must be blocked."""
        with pytest.raises(AuthorizationDeniedError, match="Invalid or missing authentication"):
            shield.execute(
                action="transfer_money",
                params={"amount": 100, "recipient": "Bob", "account_number": "1234567890"},
                auth_token="not.a.valid.jwt.token"
            )

    def test_forged_signature_token_blocked(self, shield):
        """Token signed with an attacker's private key must be rejected."""
        attacker_token = create_token(secret="attacker-forged-secret-key-32-chars!")
        with pytest.raises(AuthorizationDeniedError, match="Invalid or missing authentication"):
            shield.execute(
                action="transfer_money",
                params={"amount": 100, "recipient": "Bob", "account_number": "1234567890"},
                auth_token=attacker_token
            )

    def test_expired_token_blocked(self, shield):
        """Expired JWT token must be rejected."""
        expired_token = create_token(expires_in_hours=-2)
        with pytest.raises(AuthorizationDeniedError, match="Invalid or missing authentication"):
            shield.execute(
                action="transfer_money",
                params={"amount": 100, "recipient": "Bob", "account_number": "1234567890"},
                auth_token=expired_token
            )

    def test_token_missing_user_id_blocked(self, shield):
        """Token payload missing user_id field must be rejected."""
        now = datetime.now(timezone.utc)
        payload = {
            "agent_id": "agent_1",
            "roles": ["employee"],
            "iat": now,
            "exp": now + timedelta(hours=1)
        }
        token = jwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")
        with pytest.raises(AuthorizationDeniedError, match="Invalid or missing authentication"):
            shield.execute(
                action="transfer_money",
                params={"amount": 100, "recipient": "Bob", "account_number": "1234567890"},
                auth_token=token
            )

    def test_token_missing_agent_id_blocked(self, shield):
        """Token payload missing agent_id field must be rejected."""
        now = datetime.now(timezone.utc)
        payload = {
            "user_id": "user_1",
            "roles": ["employee"],
            "iat": now,
            "exp": now + timedelta(hours=1)
        }
        token = jwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")
        with pytest.raises(AuthorizationDeniedError, match="Invalid or missing authentication"):
            shield.execute(
                action="transfer_money",
                params={"amount": 100, "recipient": "Bob", "account_number": "1234567890"},
                auth_token=token
            )

    def test_algorithm_none_attack_blocked(self, shield):
        """Token using unsecured 'none' algorithm must be rejected."""
        now = datetime.now(timezone.utc)
        payload = {
            "user_id": "admin_user",
            "agent_id": "admin_agent",
            "roles": ["admin"],
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=1)).timestamp())
        }
        # In modern pyjwt, algorithm="none" requires options or will fail on verification
        try:
            unsecured_token = jwt.encode(payload, key="", algorithm="none")
        except Exception:
            # If pyjwt forbids encoding with none, craft the header manually
            import base64
            import json
            header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
            body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
            unsecured_token = f"{header}.{body}."

        with pytest.raises(AuthorizationDeniedError, match="Invalid or missing authentication"):
            shield.execute(
                action="transfer_money",
                params={"amount": 100, "recipient": "Bob", "account_number": "1234567890"},
                auth_token=unsecured_token
            )
