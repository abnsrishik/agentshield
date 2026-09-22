"""
LangGraph Finance Graph Workflow for AgentShield Integration.

Demonstrates an autonomous agent built using LangGraph StateGraph,
governed by AgentShield. Application-specific workflow logic lives here,
completely separate from AgentShield core.

Graph Workflow:
  START
    ↓
  agent_reasoning (Autonomous planner selects tool and arguments)
    ↓
  governed_execution (Invokes AgentShieldTool → Enforces Policy & Gateway)
    ↓
  decision
    ├─ ALLOW             → execute → COMPLETED → END
    ├─ BLOCK             → report  → BLOCKED   → END
    └─ REQUIRE_APPROVAL  → human_approval_pause (interrupt)
                             ↓
                        [Human Approval in AgentShield Store]
                             ↓
                        resume
                             ↓
                        AgentShield verification (hash + identity + single-use)
                             ↓
                        execute → COMPLETED / BLOCKED → END
"""

from typing import Any, Dict, List, Optional, TypedDict
from langgraph.graph import StateGraph, START, END
from langgraph.types import interrupt
from langgraph.checkpoint.memory import MemorySaver

from agentshield.adapters.langgraph import AgentShieldTool


class FinanceAgentState(TypedDict):
    """State schema for the LangGraph Finance Agent."""
    task: str
    tool_name: Optional[str]
    tool_args: Optional[Dict[str, Any]]
    tool_result: Optional[Dict[str, Any]]
    approval_id: Optional[str]
    status: str
    response: Optional[str]
    messages: List[Dict[str, Any]]


def default_planner(task: str) -> Dict[str, Any]:
    """
    Model-independent deterministic reasoning planner.
    Can be replaced with any LLM (e.g. ChatOpenAI, ChatAnthropic) via the model param.
    """
    task_lower = task.lower()
    if "export" in task_lower or "customer" in task_lower:
        return {
            "tool_name": "export_customer_data",
            "tool_args": {"format": "csv"},
        }
    if "50000" in task_lower or "50,000" in task_lower:
        return {
            "tool_name": "transfer_money",
            "tool_args": {
                "amount": 50000.0,
                "recipient": "Industrial Equipment Ltd",
                "account_number": "1234567890",
            },
        }
    if "20000" in task_lower or "20,000" in task_lower:
        return {
            "tool_name": "transfer_money",
            "tool_args": {
                "amount": 20000.0,
                "recipient": "Vendor Delta",
                "account_number": "1234567890",
            },
        }
    if "5000" in task_lower or "5,000" in task_lower:
        return {
            "tool_name": "transfer_money",
            "tool_args": {
                "amount": 5000.0,
                "recipient": "Office Supplies Co",
                "account_number": "1234567890",
            },
        }
    return {
        "tool_name": "transfer_money",
        "tool_args": {
            "amount": 1000.0,
            "recipient": "General Vendor",
            "account_number": "1234567890",
        },
    }


def build_finance_graph(
    shield: Any,
    tools: Dict[str, AgentShieldTool],
    checkpointer: Optional[Any] = None,
    model: Optional[Any] = None,
):
    """
    Build and compile a LangGraph StateGraph governing finance actions via AgentShield.

    Args:
        shield: Initialized AgentShield SDK.
        tools: Dict mapping tool_name -> AgentShieldTool.
        checkpointer: LangGraph checkpointer (defaults to MemorySaver for approval pause/resume).
        model: Optional LLM model callable for agent reasoning.

    Returns:
        Compiled LangGraph StateGraph.
    """
    saver = checkpointer or MemorySaver()

    def agent_reasoning_node(state: FinanceAgentState) -> Dict[str, Any]:
        """Agent analyzes user task and selects tool + parameters."""
        task = state["task"]
        if model is not None:
            # Delegate to provided model/planner
            plan = model(task)
        else:
            plan = default_planner(task)

        return {
            "tool_name": plan["tool_name"],
            "tool_args": plan["tool_args"],
            "status": "PLAN_READY",
        }

    def governed_execution_node(state: FinanceAgentState) -> Dict[str, Any]:
        """
        Executes the tool call via AgentShieldTool.
        AgentShield evaluates policies, identity, approvals, and logs audit events.
        """
        tool_name = state["tool_name"]
        tool_args = dict(state.get("tool_args") or {})
        approval_id = state.get("approval_id")

        if tool_name not in tools:
            return {
                "status": "ERROR",
                "response": f"Unknown tool '{tool_name}'",
                "tool_result": {"status": "ERROR", "message": f"Unknown tool {tool_name}"},
            }

        tool = tools[tool_name]
        invoke_args = dict(tool_args)
        if approval_id:
            invoke_args["approval_id"] = approval_id

        # Invoke through AgentShield adapter
        result = tool.invoke(invoke_args)

        status_code = result.get("status")
        if status_code == "REQUIRE_APPROVAL":
            return {
                "tool_result": result,
                "approval_id": result.get("approval_id"),
                "status": "PENDING_APPROVAL",
                "response": f"Action requires human approval. Approval ID: {result.get('approval_id')}",
            }
        elif status_code == "BLOCKED":
            return {
                "tool_result": result,
                "status": "BLOCKED",
                "response": f"Action BLOCKED: {result.get('message')} (Reason: {result.get('reason_code')})",
            }
        elif status_code == "SUCCESS":
            return {
                "tool_result": result,
                "status": "COMPLETED",
                "response": f"Action completed successfully via Protected Tool Gateway: {result.get('result')}",
            }
        else:
            return {
                "tool_result": result,
                "status": "ERROR",
                "response": f"Execution error: {result.get('message')}",
            }

    def human_approval_pause_node(state: FinanceAgentState) -> Dict[str, Any]:
        """
        Pauses the LangGraph execution using interrupt().
        Awaits human approval in the AgentShield approval store.
        """
        approval_id = state.get("approval_id")
        action = state.get("tool_name")
        params = state.get("tool_args")

        # Emit interrupt signal to LangGraph runner
        resume_payload = interrupt({
            "type": "HUMAN_APPROVAL_REQUIRED",
            "approval_id": approval_id,
            "action": action,
            "parameters": params,
            "message": "Human manager approval is required to proceed with this sensitive action.",
        })

        # When resumed, resume_payload may contain updated params (e.g. for testing tampering)
        # or explicit approval_id confirmation. AgentShield remains the sole authority.
        updates = {"status": "RESUMED"}
        if isinstance(resume_payload, dict):
            if "tamper_args" in resume_payload:
                updates["tool_args"] = resume_payload["tamper_args"]
            if "approval_id" in resume_payload:
                updates["approval_id"] = resume_payload["approval_id"]

        return updates

    def route_governance_decision(state: FinanceAgentState) -> str:
        """Routes execution based on AgentShield decision."""
        if state.get("status") == "PENDING_APPROVAL":
            return "human_approval_pause"
        return END

    workflow = StateGraph(FinanceAgentState)
    workflow.add_node("agent_reasoning", agent_reasoning_node)
    workflow.add_node("governed_execution", governed_execution_node)
    workflow.add_node("human_approval_pause", human_approval_pause_node)

    workflow.add_edge(START, "agent_reasoning")
    workflow.add_edge("agent_reasoning", "governed_execution")
    workflow.add_conditional_edges(
        "governed_execution",
        route_governance_decision,
        {"human_approval_pause": "human_approval_pause", END: END},
    )
    workflow.add_edge("human_approval_pause", "governed_execution")

    return workflow.compile(checkpointer=saver)
