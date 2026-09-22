"""
AgentShield Tool Registry and Validator.

Defines protected tools with strict parameter schemas.
Validates inputs before policy evaluation.
"""

from typing import Any, Callable, Dict, Type
from pydantic import BaseModel, ValidationError

from ..core.models import ToolDefinition, SensitivityLevel, ActionRequest
from ..core.exceptions import ToolValidationError


class ToolRegistry:
    """
    Registry for protected tool definitions and executors.
    """

    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}
        self._executors: Dict[str, Callable] = {}

    def register(
        self,
        name: str,
        schema: Type[BaseModel],
        executor: Callable[[Any], Any],
        description: str = "",
        sensitivity_level: SensitivityLevel = SensitivityLevel.MEDIUM,
        endpoint: str = None
    ):
        """
        Register a protected tool.
        
        Args:
            name: Unique tool identifier.
            schema: Pydantic model class for parameter validation.
            executor: Function to execute the tool.
            description: Human-readable description.
            sensitivity_level: Risk classification.
            endpoint: Optional gateway endpoint.
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
        self._executors[name] = executor

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

    def has_tool(self, name: str) -> bool:
        """Check if tool is registered."""
        return name in self._tools


class ToolValidator:
    """
    Validates action parameters against tool schemas.
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
        
        try:
            # Validate parameters
            validated_data = schema_class(**parameters)
            return validated_data
        except ValidationError as e:
            raise ToolValidationError(
                reason_code="SCHEMA_VALIDATION_FAILED",
                message=f"Parameter validation failed for {action_name}: {str(e)}"
            ) from e
