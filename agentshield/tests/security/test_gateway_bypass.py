"""Security tests: Attempted bypass of the Protected Tool Gateway boundary."""

import pytest
import httpx
from server.main import app
from tests.conftest import GATEWAY_AUTH_TOKEN


class TestGatewayBypassSecurity:
    """Tests verifying the application-level trust boundary at the gateway."""

    def test_missing_gateway_auth_returns_401(self, gateway_client):
        """Direct call to gateway without X-AgentShield-Auth header must return 401."""
        resp = gateway_client.post(
            "/tools/transfer_money",
            json={"amount": 100, "recipient": "Bob", "account_number": "1234567890"},
            params={"request_id": "bypass-1"}
        )
        assert resp.status_code == 401
        assert "Missing internal authentication token" in resp.json()["detail"]

    def test_invalid_gateway_auth_returns_403(self, gateway_client):
        """Direct call to gateway with wrong credential must return 403."""
        resp = gateway_client.post(
            "/tools/transfer_money",
            headers={"X-AgentShield-Auth": "wrong-secret-attacker-token"},
            json={"amount": 100, "recipient": "Bob", "account_number": "1234567890"},
            params={"request_id": "bypass-2"}
        )
        assert resp.status_code == 403
        assert "Invalid internal authentication token" in resp.json()["detail"]

    def test_valid_gateway_auth_accepted(self, gateway_client):
        """Direct call with valid internal credentials is accepted."""
        resp = gateway_client.post(
            "/tools/transfer_money",
            headers={"X-AgentShield-Auth": GATEWAY_AUTH_TOKEN},
            json={"amount": 100, "recipient": "Bob", "account_number": "1234567890"},
            params={"request_id": "valid-call-1"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True

    def test_unknown_gateway_endpoint_returns_404(self, gateway_client):
        """Direct call to non-existent tool endpoint returns 404."""
        resp = gateway_client.post(
            "/tools/non_existent_service",
            headers={"X-AgentShield-Auth": GATEWAY_AUTH_TOKEN},
            json={"data": "test"},
            params={"request_id": "unknown-1"}
        )
        assert resp.status_code == 404

    def test_unauthorized_agent_cannot_access_gateway_directly(self, gateway_client):
        """
        Simulate an AI agent attempting to send its user JWT directly to the gateway.
        The gateway expects X-AgentShield-Auth (which only AgentShield holds), not a user JWT.
        """
        user_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        resp = gateway_client.post(
            "/tools/transfer_money",
            headers={"Authorization": f"Bearer {user_jwt}"},
            json={"amount": 100, "recipient": "Bob", "account_number": "1234567890"},
            params={"request_id": "agent-bypass-attempt"}
        )
        # Must be 401 because X-AgentShield-Auth header is absent
        assert resp.status_code == 401
