"""
Integration tests for AgentShield LangGraph / LangChain Adapter and StateGraph Governance.
"""

import pytest
from unittest.mock import patch
from langgraph.types import Command
from langgraph.checkpoint.memory import MemorySaver

from agentshield.adapters.langgraph import (
    AgentShieldTool,
    create_langgraph_tool,
    create_governed_toolset,
)
from examples.langgraph_finance_graph import build_finance_graph
from tests.conftest import create_token


class TestLangGraphIntegration:
    """Test suite verifying AgentShield governance over LangGraph agents."""

    def test_tool_schema_reflection(self, shield):
        """1. Verify dynamic schema generation and field reflection from ToolDefinition."""
        token = create_token()
        tool = create_langgraph_tool(shield=shield, tool_name="transfer_money", auth_token=token)

        assert isinstance(tool, AgentShieldTool)
        assert tool.name == "transfer_money"
        assert tool.args_schema is not None

        fields = tool.args_schema.model_fields
        # Original schema fields preserved
        assert "amount" in fields
        assert "recipient" in fields
        assert "account_number" in fields
        # Dynamic governance field added
        assert "approval_id" in fields

    def test_langgraph_allowed_execution(self, shield):
        """2. Verify allowed tool execution flows through AgentShield to Gateway."""
        token = create_token()
        tool = create_langgraph_tool(shield=shield, tool_name="transfer_money", auth_token=token)

        result = tool.invoke({
            "amount": 5000,
            "recipient": "Office Supplies Co",
            "account_number": "1234567890",
        })

        assert result["status"] == "SUCCESS"
        assert result["decision"] == "ALLOW"
        assert result["result"]["status"] == "success"
        assert result["result"]["amount"] == 5000.0
        assert result["result"]["remaining_balance"] == 95000.0

    def test_langgraph_blocked_execution(self, shield):
        """3. Verify unauthorized tool call is blocked by AgentShield policy and reported to LangGraph."""
        token = create_token()
        tool = create_langgraph_tool(shield=shield, tool_name="export_customer_data", auth_token=token)

        result = tool.invoke({"format": "csv"})

        assert result["status"] == "BLOCKED"
        assert result["decision"] == "BLOCK"
        assert result["reason_code"] == "POLICY_BLOCK"
        assert "blocked by organizational policy" in result["message"]

    def test_langgraph_approval_required_execution(self, shield):
        """4. Verify policy limit breach returns REQUIRE_APPROVAL without executing."""
        token = create_token()
        tool = create_langgraph_tool(shield=shield, tool_name="transfer_money", auth_token=token)

        result = tool.invoke({
            "amount": 50000,
            "recipient": "Industrial Equipment Ltd",
            "account_number": "1234567890",
        })

        assert result["status"] == "REQUIRE_APPROVAL"
        assert result["decision"] == "REQUIRE_APPROVAL"
        assert result["reason_code"] == "APPROVAL_REQUIRED"
        assert result["approval_id"] is not None
        assert len(result["approval_id"]) > 0

    def test_graph_actually_pauses_on_approval(self, shield):
        """5. Verify LangGraph StateGraph interrupts/pauses when approval is required."""
        token = create_token()
        tools_dict = {
            "transfer_money": create_langgraph_tool(shield=shield, tool_name="transfer_money", auth_token=token),
            "export_customer_data": create_langgraph_tool(shield=shield, tool_name="export_customer_data", auth_token=token),
        }

        graph = build_finance_graph(shield=shield, tools=tools_dict, checkpointer=MemorySaver())
        config = {"configurable": {"thread_id": "thread-pause-test-01"}}

        state = graph.invoke(
            {"task": "Transfer ₹50,000 to Industrial Equipment Ltd"},
            config=config,
        )

        # Graph must be in an interrupted/paused state waiting for human approval
        assert "__interrupt__" in state
        interrupts = state["__interrupt__"]
        assert len(interrupts) > 0
        assert interrupts[0].value["type"] == "HUMAN_APPROVAL_REQUIRED"
        assert state["status"] == "PENDING_APPROVAL"
        assert state["approval_id"] is not None

    def test_graph_resumes_after_valid_approval(self, shield):
        """6. Verify paused graph resumes and executes through gateway after human approval."""
        token = create_token()
        tools_dict = {
            "transfer_money": create_langgraph_tool(shield=shield, tool_name="transfer_money", auth_token=token),
        }

        graph = build_finance_graph(shield=shield, tools=tools_dict, checkpointer=MemorySaver())
        config = {"configurable": {"thread_id": "thread-resume-test-02"}}

        # Step 1: Trigger pause
        paused_state = graph.invoke(
            {"task": "Transfer ₹50,000 to Industrial Equipment Ltd"},
            config=config,
        )
        approval_id = paused_state["approval_id"]

        # Step 2: Human manager approves the request in AgentShield store
        shield.approve_request(approval_id, approver_id="manager_sarah")

        # Step 3: Resume graph with the approval confirmation
        resumed_state = graph.invoke(
            Command(resume={"approval_id": approval_id}),
            config=config,
        )

        assert resumed_state["status"] == "COMPLETED"
        assert resumed_state["tool_result"]["status"] == "SUCCESS"
        assert resumed_state["tool_result"]["result"]["amount"] == 50000.0

    def test_tampered_approval_is_rejected(self, shield):
        """7. Verify tampered arguments on resume are rejected by AgentShield request_hash check."""
        token = create_token()
        tools_dict = {
            "transfer_money": create_langgraph_tool(shield=shield, tool_name="transfer_money", auth_token=token),
        }

        graph = build_finance_graph(shield=shield, tools=tools_dict, checkpointer=MemorySaver())
        config = {"configurable": {"thread_id": "thread-tamper-test-03"}}

        # Step 1: Trigger pause for ₹20,000
        paused_state = graph.invoke(
            {"task": "Transfer ₹20,000 to Vendor Delta"},
            config=config,
        )
        approval_id = paused_state["approval_id"]

        # Step 2: Human manager approves the ₹20,000 transfer
        shield.approve_request(approval_id, approver_id="manager_sarah")

        # Step 3: Adversary alters amount to ₹99,000 on resume
        resumed_state = graph.invoke(
            Command(resume={
                "approval_id": approval_id,
                "tamper_args": {
                    "amount": 99000.0,
                    "recipient": "Vendor Delta",
                    "account_number": "1234567890",
                },
            }),
            config=config,
        )

        # AgentShield must detect the hash mismatch and reject execution
        assert resumed_state["status"] == "BLOCKED"
        assert resumed_state["tool_result"]["status"] == "BLOCKED"
        assert resumed_state["tool_result"]["reason_code"] == "REQUEST_HASH_MISMATCH"

    def test_gateway_not_contacted_while_approval_pending(self, shield, gateway_executor):
        """8. Verify gateway is never called when policy requires approval."""
        token = create_token()
        tool = create_langgraph_tool(shield=shield, tool_name="transfer_money", auth_token=token)

        with patch.object(gateway_executor, "execute") as mock_exec:
            res = tool.invoke({
                "amount": 50000,
                "recipient": "Industrial Equipment Ltd",
                "account_number": "1234567890",
            })
            assert res["status"] == "REQUIRE_APPROVAL"
            mock_exec.assert_not_called()

    def test_end_to_end_stategraph_execution(self, shield):
        """9. Verify end-to-end autonomous flow: reasoning -> governed execution -> completed."""
        token = create_token()
        governed_tools = create_governed_toolset(shield=shield, auth_token=token)
        tools_dict = {t.name: t for t in governed_tools}

        graph = build_finance_graph(shield=shield, tools=tools_dict, checkpointer=MemorySaver())
        config = {"configurable": {"thread_id": "thread-e2e-04"}}

        result = graph.invoke(
            {"task": "Please transfer ₹5,000 to Office Supplies Co for office items."},
            config=config,
        )

        assert result["status"] == "COMPLETED"
        assert result["tool_name"] == "transfer_money"
        assert result["tool_result"]["status"] == "SUCCESS"
        assert "completed successfully" in result["response"]
