"""
Unit tests for AgentShield Tool Registry and Validator.
"""
import pytest
from pydantic import BaseModel, Field

from agentshield.tools.registry import ToolRegistry, ToolValidator
from agentshield.core.models import SensitivityLevel
from agentshield.core.exceptions import ToolValidationError


class TransferMoneyParams(BaseModel):
    """Test schema for transfer_money tool."""
    amount: float = Field(gt=0, description="Amount must be positive")
    recipient: str = Field(min_length=1, description="Recipient name")


class EmailParams(BaseModel):
    """Test schema for send_email tool."""
    to: str
    subject: str
    body: str


class TestToolRegistry:
    """Test ToolRegistry functionality."""
    
    def test_register_tool_success(self):
        """Should register a tool successfully."""
        registry = ToolRegistry()
        registry.register(
            name="transfer_money",
            schema=TransferMoneyParams,
            executor=lambda x: None,
            description="Transfer funds",
            sensitivity_level=SensitivityLevel.HIGH
        )
        
        assert registry.has_tool("transfer_money") is True
        tool = registry.get_tool("transfer_money")
        assert tool.name == "transfer_money"
        assert tool.sensitivity_level == SensitivityLevel.HIGH
    
    def test_register_duplicate_tool_raises(self):
        """Registering duplicate tool should raise error."""
        registry = ToolRegistry()
        registry.register(
            name="test_tool",
            schema=TransferMoneyParams,
            executor=lambda x: None
        )
        
        with pytest.raises(ValueError, match="already registered"):
            registry.register(
                name="test_tool",
                schema=TransferMoneyParams,
                executor=lambda x: None
            )
    
    def test_get_unknown_tool_raises(self):
        """Getting unknown tool should raise ToolValidationError."""
        registry = ToolRegistry()
        
        with pytest.raises(ToolValidationError, match="Unknown tool"):
            registry.get_tool("nonexistent")
    
    def test_get_executor_success(self):
        """Should retrieve registered executor."""
        registry = ToolRegistry()
        mock_executor = lambda x: {"result": "success"}
        
        registry.register(
            name="test_action",
            schema=TransferMoneyParams,
            executor=mock_executor
        )
        
        executor = registry.get_executor("test_action")
        assert executor == mock_executor


class TestToolValidator:
    """Test ToolValidator functionality."""
    
    @pytest.fixture
    def populated_registry(self):
        """Create registry with test tools."""
        registry = ToolRegistry()
        registry.register(
            name="transfer_money",
            schema=TransferMoneyParams,
            executor=lambda x: None,
            description="Transfer funds"
        )
        registry.register(
            name="send_email",
            schema=EmailParams,
            executor=lambda x: None,
            description="Send email"
        )
        return registry
    
    def test_validate_success(self, populated_registry):
        """Valid parameters should pass validation."""
        validator = ToolValidator(populated_registry)
        
        params = {"amount": 5000.0, "recipient": "ABC Corp"}
        validated = validator.validate("transfer_money", params)
        
        assert validated.amount == 5000.0
        assert validated.recipient == "ABC Corp"
    
    def test_validate_missing_required_field(self, populated_registry):
        """Missing required field should fail validation."""
        validator = ToolValidator(populated_registry)
        
        params = {"amount": 5000.0}  # Missing 'recipient'
        
        with pytest.raises(ToolValidationError, match="validation failed"):
            validator.validate("transfer_money", params)
    
    def test_validate_wrong_type(self, populated_registry):
        """Wrong type should fail validation."""
        validator = ToolValidator(populated_registry)
        
        params = {"amount": "not_a_number", "recipient": "ABC"}
        
        with pytest.raises(ToolValidationError):
            validator.validate("transfer_money", params)
    
    def test_validate_constraint_violation(self, populated_registry):
        """Constraint violation (amount <= 0) should fail."""
        validator = ToolValidator(populated_registry)
        
        params = {"amount": -100, "recipient": "ABC"}  # amount must be > 0
        
        with pytest.raises(ToolValidationError):
            validator.validate("transfer_money", params)
    
    def test_validate_extra_fields_rejected(self, populated_registry):
        """Extra undeclared fields should be rejected."""
        validator = ToolValidator(populated_registry)
        
        # Add extra field not in schema
        params = {
            "amount": 5000.0,
            "recipient": "ABC",
            "extra_field": "should_fail"
        }
        
        with pytest.raises(ToolValidationError):
            validator.validate("transfer_money", params)
    
    def test_validate_unknown_tool(self, populated_registry):
        """Validating against unknown tool should fail."""
        validator = ToolValidator(populated_registry)
        
        with pytest.raises(ToolValidationError, match="Unknown tool"):
            validator.validate("nonexistent_tool", {"param": "value"})
    
    def test_validate_string_length_constraint(self, populated_registry):
        """String length constraints should be enforced."""
        validator = ToolValidator(populated_registry)
        
        # recipient has min_length=1
        params = {"amount": 100, "recipient": ""}
        
        with pytest.raises(ToolValidationError):
            validator.validate("transfer_money", params)
