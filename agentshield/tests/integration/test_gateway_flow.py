"""Integration tests for Protected Tool Gateway execution boundary."""

import pytest
import httpx
from unittest.mock import patch

from agentshield.core.exceptions import ToolExecutionError, GatewayConnectionError
from agentshield.adapters.gateway_executor import GatewayExecutor
from tests.conftest import create_token, GATEWAY_AUTH_TOKEN


class TestGatewayFlow:
    """Tests proving the gateway boundary and execution flow."""

    def test_gateway_health_check(self, gateway_executor):
        """Gateway should report healthy."""
        assert gateway_executor.health_check() is True

    def test_allowed_action_executes_via_gateway(self, shield):
        """
        Action authorized by policy should flow through GatewayExecutor to Mock Banking API.
        Verify balance is deducted and transaction details returned.
        """
        token = create_token()
        result = shield.execute(
            action="transfer_money",
            params={
                "amount": 2500,
                "recipient": "Bob",
                "account_number": "1234567890"
            },
            auth_token=token
        )

        assert result["status"] == "success"
        assert result["amount"] == 2500
        assert result["recipient"] == "Bob"
        assert result["remaining_balance"] == 97500.0

    def test_gateway_idempotency_same_params(self, shield, gateway_executor):
        """
        Repeating an execution with identical request_id and parameters should return
        the cached result without re-executing (balance must NOT decrease a second time).
        """
        token = create_token()
        params = {
            "amount": 1000,
            "recipient": "Charlie",
            "account_number": "1234567890"
        }

        # Direct execution via GatewayExecutor to control request_id explicitly
        req_id = "test-idempotent-req-001"
        res1 = gateway_executor.execute("transfer_money", params, request_id=req_id)
        assert res1["status"] == "success"
        balance_after_first = res1["remaining_balance"]

        # Call again with identical parameters and identical request_id
        res2 = gateway_executor.execute("transfer_money", params, request_id=req_id)
        assert res2["status"] == "success"
        # The remaining balance returned must match the first call (cached)
        assert res2["remaining_balance"] == balance_after_first

    def test_gateway_idempotency_conflict_different_params(self, gateway_executor):
        """
        Reusing the same request_id with DIFFERENT parameters must be rejected with 409 conflict.
        """
        req_id = "test-conflict-req-002"
        params1 = {
            "amount": 1000,
            "recipient": "Alice",
            "account_number": "1234567890"
        }
        params2 = {
            "amount": 2000,  # Different amount
            "recipient": "Alice",
            "account_number": "1234567890"
        }

        gateway_executor.execute("transfer_money", params1, request_id=req_id)

        # Attempt replay with different amount using same request_id
        with pytest.raises(ToolExecutionError, match="Request ID conflict"):
            gateway_executor.execute("transfer_money", params2, request_id=req_id)

    def test_customer_tools_via_gateway(self, gateway_executor):
        """Customer lookup and search should work through the gateway."""
        # Search customers
        search_res = gateway_executor.execute(
            "search_customers",
            {"name_contains": "Alice"},
            request_id="search-req-001"
        )
        assert search_res["count"] >= 1
        assert any(c["id"] == "C001" for c in search_res["customers"])

        # Customer lookup
        cust_res = gateway_executor.execute(
            "get_customer",
            {"customer_id": "C001"},
            request_id="get-req-001"
        )
        assert cust_res["id"] == "C001"
        assert cust_res["name"] == "Alice Sharma"

    def test_gateway_unreachable_safe_failure(self):
        """If gateway is unreachable, execution must fail safely with GatewayConnectionError."""
        # Point executor to a dead port
        dead_executor = GatewayExecutor(
            base_url="http://127.0.0.1:59999",
            auth_token=GATEWAY_AUTH_TOKEN,
            timeout=1.0
        )
        with pytest.raises(GatewayConnectionError, match="Cannot connect to gateway"):
            dead_executor.execute(
                "transfer_money",
                {"amount": 100, "recipient": "Bob", "account_number": "1234567890"},
                request_id="fail-req-001"
            )

    def test_gateway_timeout_safe_failure(self, gateway_executor):
        """If gateway times out, execution must fail safely with GatewayConnectionError."""
        from unittest.mock import patch, MagicMock
        from contextlib import nullcontext
        mock_client = MagicMock()
        mock_client.post.side_effect = httpx.TimeoutException("Simulated gateway timeout")

        with patch.object(gateway_executor, "_get_client", return_value=nullcontext(mock_client)):
            with pytest.raises(GatewayConnectionError, match="Gateway request timed out"):
                gateway_executor.execute(
                    "transfer_money",
                    {"amount": 100, "recipient": "Bob", "account_number": "1234567890"},
                    request_id="timeout-req-001"
                )


    def test_unknown_tool_rejected_by_gateway_executor(self, gateway_executor):
        """Executing an unregistered tool on gateway should be rejected immediately."""
        with pytest.raises(ToolExecutionError, match="Unknown tool: non_existent_tool"):
            gateway_executor.execute(
                "non_existent_tool",
                {"foo": "bar"},
                request_id="unknown-tool-001"
            )
