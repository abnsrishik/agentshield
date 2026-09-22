"""
AgentShield Tool Registry and Validator.

Defines protected tools with strict parameter schemas.
Validates inputs before policy evaluation.
"""

from typing import Any, Callable, Dict, Type, Optional
from pydantic import BaseModel, ValidationError

from ..core.models import ToolDefinition, SensitivityLevel, ActionRequest
from ..core.exceptions import ToolValidationError
from ..adapters.gateway_executor import BaseToolExecutor, LocalExecutor


class ToolRegistry:
    """
    Registry for protected tool definitions and executors.
    """

    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}
        self._executors: Dict[str, Callable] = {}
        self._strategies: Dict[str, BaseToolExecutor] = {}

    def register(
        self,
        name: str,
        schema: Type[BaseModel],
        executor: Optional[Callable[[Any], Any]] = None,
        description: str = "",
        sensitivity_level: SensitivityLevel = SensitivityLevel.MEDIUM,
        endpoint: Optional[str] = None,
        executor_strategy: Optional[BaseToolExecutor] = None
    ):
        """
        Register a protected tool.
        
        Args:
            name: Unique tool identifier.
            schema: Pydantic model class for parameter validation.
            executor: Optional local function to execute the tool (testing adapter).
            description: Human-readable description.
            sensitivity_level: Risk classification.
            endpoint: Optional gateway endpoint.
            executor_strategy: Optional custom execution strategy (e.g. GatewayExecutor).
        """
        if name in self._tools:
            raise ValueError(f"Tool '{name}' is already registered")
        
        self._tools[name] = ToolDefinition(
            name=name,
            description=description,
            parameter_schema=schema,
            sensitivity_level=sensitivity_level,
            endpoint=endpoint
        )
        if executor is not None:
            self._executors[name] = executor
            self._strategies[name] = LocalExecutor(executor)
        if executor_strategy is not None:
            self._strategies[name] = executor_strategy

    def get_tool(self, name: str) -> ToolDefinition:
        """Get tool definition by name."""
        if name not in self._tools:
            raise ToolValidationError(
                reason_code="UNKNOWN_TOOL",
                message=f"Unknown tool: {name}"
            )
        return self._tools[name]

    def get_executor(self, name: str) -> Callable:
        """Get tool executor by name."""
        if name not in self._executors:
            raise ToolValidationError(
                reason_code="UNKNOWN_TOOL",
                message=f"Unknown tool: {name}"
            )
        return self._executors[name]

    def get_executor_strategy(self, name: str) -> Optional[BaseToolExecutor]:
        """Get tool execution strategy by name."""
        if name not in self._tools:
            raise ToolValidationError(
                reason_code="UNKNOWN_TOOL",
                message=f"Unknown tool: {name}"
            )
        return self._strategies.get(name)

    def has_tool(self, name: str) -> bool:
        """Check if tool is registered."""
        return name in self._tools

    def has_executor(self, name: str) -> bool:
        """Check if an executor or strategy is registered for this tool."""
        return name in self._executors or name in self._strategies



class ToolValidator:
    """
    Validates action parameters against tool schemas.
    Explicitly rejects undeclared parameters.
    """

    def __init__(self, registry: ToolRegistry):
        self.registry = registry

    def validate(self, action_name: str, parameters: Dict[str, Any]) -> BaseModel:
        """
        Validate parameters against the tool's schema.
        
        Args:
            action_name: Name of the tool.
            parameters: Raw parameter dictionary.
            
        Returns:
            Validated Pydantic model instance.
            
        Raises:
            ToolValidationError: If validation fails.
        """
        # Check if tool exists
        tool_def = self.registry.get_tool(action_name)
        
        # Get schema class
        schema_class = tool_def.parameter_schema
        
        # Check for extra undeclared fields BEFORE validation
        # This satisfies requirement #4: ToolValidator explicitly rejects undeclared parameters
        declared_fields = set(schema_class.model_fields.keys())
        provided_fields = set(parameters.keys())
        extra_fields = provided_fields - declared_fields
        
        if extra_fields:
            raise ToolValidationError(
                reason_code="EXTRA_FIELDS_NOT_ALLOWED",
                message=f"Undeclared parameters for {action_name}: {extra_fields}"
            )
        
        try:
            # Validate parameters
            validated_data = schema_class(**parameters)
            return validated_data
        except ValidationError as e:
            raise ToolValidationError(
                reason_code="SCHEMA_VALIDATION_FAILED",
                message=f"Parameter validation failed for {action_name}: {str(e)}"
            ) from e
