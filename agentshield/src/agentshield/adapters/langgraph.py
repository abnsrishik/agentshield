"""
AgentShield LangGraph / LangChain Adapter.

Exposes AgentShield protected tools as native LangChain BaseTool instances.
All tool invocations are intercepted and governed by AgentShield SDK,
routing through Identity Verification, Policy Engine, Approval Store,
Fail-Closed Audit, and GatewayExecutor.

Core AgentShield modules remain completely independent of LangChain/LangGraph.
"""

from typing import Any, Callable, Dict, List, Optional, Type
from pydantic import BaseModel, ConfigDict, Field, create_model

try:
    from langchain_core.tools import BaseTool
except ImportError as exc:
    raise ImportError(
        "langchain-core is required to use the AgentShield LangGraph adapter. "
        "Install it via: pip install 'agentshield[demo]'"
    ) from exc

from ..core.exceptions import (
    ApprovalExpiredError,
    ApprovalRequiredError,
    ApprovalTamperError,
    AuthorizationDeniedError,
    IdentityVerificationError,
    ToolExecutionError,
    ToolValidationError,
)


class AgentShieldTool(BaseTool):
    """
    LangChain BaseTool wrapper for an AgentShield-governed protected tool.

    Intercepts all execution requests from autonomous agents and delegates
    them to AgentShield.execute(), enforcing deny-by-default policies,
    parameter validation, human approval workflows, and gateway boundaries.
    """

    name: str
    description: str
    shield: Any = Field(description="AgentShield instance")
    auth_token: Optional[str] = Field(default=None, description="JWT authentication token for the agent")
    token_provider: Optional[Callable[[], str]] = Field(default=None, description="Callable returning active JWT")
    approval_id: Optional[str] = Field(default=None, description="Approval ID to bind to execution")
    return_error_dict: bool = Field(default=True, description="Return structured governance dict on security rejection")

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def _get_token(self) -> str:
        """Resolve active JWT token from static field or dynamic provider."""
        if self.token_provider is not None:
            return self.token_provider()
        if self.auth_token is not None:
            return self.auth_token
        raise IdentityVerificationError("No auth_token or token_provider configured on AgentShieldTool")

    def _run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """
        Synchronous tool execution path invoked by LangGraph / LangChain.
        Delegates strictly to AgentShield.execute().
        """
        # Separate approval_id from tool parameters so parameter hash binding is exact
        approval_id = kwargs.pop("approval_id", None) or self.approval_id
        auth_token = kwargs.pop("auth_token", None)

        try:
            token = auth_token or self._get_token()
        except IdentityVerificationError as e:
            if not self.return_error_dict:
                raise
            return {
                "status": "BLOCKED",
                "decision": "BLOCK",
                "reason_code": "IDENTITY_VERIFICATION_FAILED",
                "message": str(e),
                "action": self.name,
            }

        # Parameters are validated strictly by AgentShield.execute against the registered schema
        try:
            result = self.shield.execute(
                action=self.name,
                params=kwargs,
                auth_token=token,
                approval_id=approval_id,
            )
            return {
                "status": "SUCCESS",
                "decision": "ALLOW",
                "action": self.name,
                "result": result,
            }
        except ApprovalRequiredError as e:
            if not self.return_error_dict:
                raise
            return {
                "status": "REQUIRE_APPROVAL",
                "decision": "REQUIRE_APPROVAL",
                "approval_id": e.approval_id,
                "reason_code": "APPROVAL_REQUIRED",
                "message": e.message,
                "action": self.name,
                "parameters": kwargs,
            }
        except ApprovalTamperError as e:
            if not self.return_error_dict:
                raise
            return {
                "status": "BLOCKED",
                "decision": "BLOCK",
                "reason_code": e.reason_code,
                "message": e.message,
                "action": self.name,
            }
        except ApprovalExpiredError as e:
            if not self.return_error_dict:
                raise
            return {
                "status": "BLOCKED",
                "decision": "BLOCK",
                "reason_code": e.reason_code,
                "message": e.message,
                "action": self.name,
            }
        except AuthorizationDeniedError as e:
            if not self.return_error_dict:
                raise
            return {
                "status": "BLOCKED",
                "decision": "BLOCK",
                "reason_code": e.reason_code,
                "message": e.message,
                "action": self.name,
            }
        except ToolValidationError as e:
            if not self.return_error_dict:
                raise
            return {
                "status": "VALIDATION_ERROR",
                "decision": "BLOCK",
                "reason_code": e.reason_code,
                "message": e.message,
                "action": self.name,
            }
        except ToolExecutionError as e:
            if not self.return_error_dict:
                raise
            return {
                "status": "ERROR",
                "decision": "EXECUTION_ERROR",
                "message": str(e),
                "action": self.name,
            }

    async def _arun(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Asynchronous execution path: calls synchronous _run."""
        return self._run(*args, **kwargs)


def _build_governed_args_schema(schema: Type[BaseModel], name: str) -> Type[BaseModel]:
    """
    Dynamically extend the registered Pydantic schema with an optional approval_id field
    so LangGraph agents can pass approval_id when retrying an approved action.
    """
    schema_name = f"Governed{schema.__name__}_{name}"
    return create_model(
        schema_name,
        approval_id=(Optional[str], Field(default=None, description="Optional approval ID issued by human manager")),
        __base__=schema,
    )


def create_langgraph_tool(
    shield: Any,
    tool_name: str,
    auth_token: Optional[str] = None,
    token_provider: Optional[Callable[[], str]] = None,
    return_error_dict: bool = True,
) -> AgentShieldTool:
    """
    Create a LangChain BaseTool from a registered AgentShield tool.

    Args:
        shield: Initialized AgentShield SDK instance.
        tool_name: Name of the tool in shield.tool_registry.
        auth_token: Optional static JWT token for the agent session.
        token_provider: Optional callable returning active JWT token.
        return_error_dict: If True, returns structured security dict on error.

    Returns:
        AgentShieldTool ready for use in LangGraph StateGraph or LangChain agents.
    """
    tool_def = shield.tool_registry.get_tool(tool_name)
    governed_schema = _build_governed_args_schema(tool_def.parameter_schema, tool_name)

    return AgentShieldTool(
        name=tool_def.name,
        description=tool_def.description or f"AgentShield governed tool: {tool_def.name}",
        args_schema=governed_schema,
        shield=shield,
        auth_token=auth_token,
        token_provider=token_provider,
        return_error_dict=return_error_dict,
    )


def create_governed_toolset(
    shield: Any,
    auth_token: Optional[str] = None,
    token_provider: Optional[Callable[[], str]] = None,
    return_error_dict: bool = True,
) -> List[AgentShieldTool]:
    """
    Convert all tools registered in AgentShield's ToolRegistry into LangChain tools.

    Args:
        shield: Initialized AgentShield SDK instance.
        auth_token: Optional static JWT token for the agent session.
        token_provider: Optional callable returning active JWT token.
        return_error_dict: If True, returns structured security dict on error.

    Returns:
        List of AgentShieldTool instances.
    """
    tools = []
    for name in shield.tool_registry._tools:
        tool = create_langgraph_tool(
            shield=shield,
            tool_name=name,
            auth_token=auth_token,
            token_provider=token_provider,
            return_error_dict=return_error_dict,
        )
        tools.append(tool)
    return tools
