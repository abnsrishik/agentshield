"""
Unit tests for AgentShield Policy Engine.
"""
import pytest
import tempfile
import os
from pathlib import Path

from agentshield.policy.engine import PolicyEngine, PolicyCondition, PolicyRule
from agentshield.core.models import ActionRequest, Principal, DecisionType
from agentshield.core.exceptions import PolicyEvaluationError


class TestPolicyCondition:
    """Test individual policy conditions."""
    
    def test_eq_operator(self):
        """Test equality operator."""
        cond = PolicyCondition(field="action", operator="eq", value="transfer_money")
        assert cond.evaluate({"action": "transfer_money"}) is True
        assert cond.evaluate({"action": "send_email"}) is False
    
    def test_gt_operator(self):
        """Test greater than operator."""
        cond = PolicyCondition(field="amount", operator="gt", value=10000)
        assert cond.evaluate({"amount": 15000}) is True
        assert cond.evaluate({"amount": 5000}) is False
        assert cond.evaluate({"amount": 10000}) is False
    
    def test_gt_with_non_numeric(self):
        """GT should return False for non-numeric values."""
        cond = PolicyCondition(field="amount", operator="gt", value=10000)
        assert cond.evaluate({"amount": "not_a_number"}) is False
    
    def test_in_operator(self):
        """Test 'in' operator."""
        cond = PolicyCondition(field="role", operator="in", value=["admin", "manager"])
        assert cond.evaluate({"role": "admin"}) is True
        assert cond.evaluate({"role": "employee"}) is False
    
    def test_not_in_operator(self):
        """Test 'not_in' operator."""
        cond = PolicyCondition(field="domain", operator="not_in", value=["company.com"])
        assert cond.evaluate({"domain": "external.com"}) is True
        assert cond.evaluate({"domain": "company.com"}) is False
    
    def test_exists_operator_true(self):
        """Test exists operator when field exists."""
        cond = PolicyCondition(field="recipient", operator="exists", value=None)
        assert cond.evaluate({"recipient": "abc@example.com"}) is True
    
    def test_exists_operator_false(self):
        """Test exists operator when field is missing."""
        cond = PolicyCondition(field="recipient", operator="exists", value=None)
        assert cond.evaluate({}) is False
    
    def test_nested_field_access(self):
        """Test accessing nested fields with dot notation."""
        cond = PolicyCondition(field="user.role", operator="eq", value="admin")
        assert cond.evaluate({"user": {"role": "admin"}}) is True
        assert cond.evaluate({"user": {"role": "user"}}) is False
    
    def test_missing_field_returns_none(self):
        """Missing fields should return None for evaluation."""
        cond = PolicyCondition(field="missing.field", operator="eq", value="test")
        # None == "test" is False
        assert cond.evaluate({"other": "value"}) is False
    
    def test_unsupported_operator_raises(self):
        """Unsupported operators should raise ValueError."""
        with pytest.raises(ValueError, match="Unsupported operator"):
            PolicyCondition(field="x", operator="regex", value="pattern")


class TestPolicyRule:
    """Test policy rule matching."""
    
    def test_rule_matches_action_wildcard(self):
        """Wildcard action matches everything."""
        rule_data = {
            "id": "test_rule",
            "match": {"action": "*"},
            "consequence": {"type": "ALLOW"}
        }
        rule = PolicyRule(rule_data)
        assert rule.matches_action("any_action") is True
        assert rule.matches_action("transfer_money") is True
    
    def test_rule_matches_specific_action(self):
        """Specific action only matches exact name."""
        rule_data = {
            "id": "test_rule",
            "match": {"action": "transfer_money"},
            "consequence": {"type": "BLOCK"}
        }
        rule = PolicyRule(rule_data)
        assert rule.matches_action("transfer_money") is True
        assert rule.matches_action("send_email") is False
    
    def test_rule_matches_all_conditions(self):
        """All conditions must match."""
        rule_data = {
            "id": "test_rule",
            "match": {
                "action": "transfer_money",
                "conditions": [
                    {"field": "amount", "operator": "gt", "value": 10000},
                    {"field": "currency", "operator": "eq", "value": "INR"}
                ]
            },
            "consequence": {"type": "REQUIRE_APPROVAL"}
        }
        rule = PolicyRule(rule_data)
        
        # Both conditions met
        data = {"action": "transfer_money", "amount": 15000, "currency": "INR"}
        assert rule.matches_conditions(data) is True
        
        # One condition fails
        data = {"action": "transfer_money", "amount": 5000, "currency": "INR"}
        assert rule.matches_conditions(data) is False
    
    def test_rule_get_consequence(self):
        """Should return correct DecisionType from consequence."""
        rule_data = {
            "id": "test",
            "match": {"action": "*"},
            "consequence": {"type": "REQUIRE_APPROVAL", "approver_role": "manager"}
        }
        rule = PolicyRule(rule_data)
        assert rule.get_consequence() == DecisionType.REQUIRE_APPROVAL
        assert rule.get_approver_role() == "manager"


class TestPolicyEngine:
    """Test full policy engine evaluation."""
    
    @pytest.fixture
    def temp_policy_dir(self):
        """Create temporary directory with test policies."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_file = Path(tmpdir) / "test_policies.yaml"
            policy_file.write_text("""
version: "1.0"
rules:
  - id: "block_large_transfer"
    match:
      action: "transfer_money"
      conditions:
        - field: "amount"
          operator: "gt"
          value: 10000
    consequence:
      type: "BLOCK"
  
  - id: "allow_small_transfer"
    match:
      action: "transfer_money"
      conditions:
        - field: "amount"
          operator: "lte"
          value: 10000
    consequence:
      type: "ALLOW"
  
  - id: "require_approval_medium"
    match:
      action: "transfer_money"
      conditions:
        - field: "amount"
          operator: "gt"
          value: 5000
        - field: "amount"
          operator: "lte"
          value: 10000
    consequence:
      type: "REQUIRE_APPROVAL"
""")
            yield tmpdir
    
    def test_load_policies_success(self, temp_policy_dir):
        """Should load policies without error."""
        engine = PolicyEngine(policy_path=temp_policy_dir)
        assert len(engine.rules) > 0
        assert engine.policy_version != ""
    
    def test_deny_by_default_no_match(self, temp_policy_dir):
        """Actions with no matching policy should be blocked."""
        engine = PolicyEngine(policy_path=temp_policy_dir)
        principal = Principal(user_id="u1", agent_id="a1")
        request = ActionRequest(
            principal=principal,
            action_name="unknown_action",  # No rules for this
            parameters={}
        )
        
        decision = engine.evaluate(request)
        assert decision.decision == DecisionType.BLOCK
        assert decision.reason_code == "NO_MATCHING_POLICY"
    
    def test_block_takes_precedence(self, temp_policy_dir):
        """BLOCK should override ALLOW in precedence."""
        engine = PolicyEngine(policy_path=temp_policy_dir)
        principal = Principal(user_id="u1", agent_id="a1")
        
        # This amount triggers both block (>10000) and potentially allow rules
        request = ActionRequest(
            principal=principal,
            action_name="transfer_money",
            parameters={"amount": 15000}
        )
        
        decision = engine.evaluate(request)
        assert decision.decision == DecisionType.BLOCK
    
    def test_require_approval_precedence_over_allow(self, temp_policy_dir):
        """REQUIRE_APPROVAL should override ALLOW."""
        # Create policy where both apply
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_file = Path(tmpdir) / "test.yaml"
            policy_file.write_text("""
version: "1.0"
rules:
  - id: "rule_allow"
    match:
      action: "test_action"
    consequence:
      type: "ALLOW"
  
  - id: "rule_approve"
    match:
      action: "test_action"
      conditions:
        - field: "flag"
          operator: "eq"
          value: true
    consequence:
      type: "REQUIRE_APPROVAL"
""")
            engine = PolicyEngine(policy_path=tmpdir)
            principal = Principal(user_id="u1", agent_id="a1")
            request = ActionRequest(
                principal=principal,
                action_name="test_action",
                parameters={"flag": True}
            )
            
            decision = engine.evaluate(request)
            # Both rules match, REQUIRE_APPROVAL > ALLOW
            assert decision.decision == DecisionType.REQUIRE_APPROVAL
    
    def test_policy_version_changes_with_content(self, temp_policy_dir):
        """Policy version hash should change when content changes."""
        engine1 = PolicyEngine(policy_path=temp_policy_dir)
        version1 = engine1.policy_version
        
        # Modify policy - add a new rule (comments are ignored by YAML parser)
        policy_file = Path(temp_policy_dir) / "test_policies.yaml"
        existing = policy_file.read_text()
        policy_file.write_text(existing + """
  - id: "new_rule_added"
    match:
      action: "test_action"
    consequence:
      type: "ALLOW"
""")
        
        engine2 = PolicyEngine(policy_path=temp_policy_dir)
        version2 = engine2.policy_version
        
        assert version1 != version2
    
    def test_invalid_yaml_raises_policy_error(self):
        """Invalid YAML should raise PolicyEvaluationError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_file = Path(tmpdir) / "bad.yaml"
            policy_file.write_text("invalid: yaml: content: [unclosed")
            
            with pytest.raises(PolicyEvaluationError):
                PolicyEngine(policy_path=tmpdir)
    
    def test_missing_policy_path_raises(self):
        """Non-existent path should raise error."""
        with pytest.raises(PolicyEvaluationError, match="does not exist"):
            PolicyEngine(policy_path="/nonexistent/path")
    
    def test_explicit_default_deny_is_skipped(self, temp_policy_dir):
        """Rules with id 'default_deny' should be skipped."""
        # Add explicit default_deny rule
        policy_file = Path(temp_policy_dir) / "test_policies.yaml"
        existing = policy_file.read_text()
        policy_file.write_text(existing + """
  - id: "default_deny"
    match:
      action: "*"
    consequence:
      type: "BLOCK"
""")
        engine = PolicyEngine(policy_path=temp_policy_dir)
        
        # The explicit default_deny should be skipped
        # But implicit deny-by-default still applies for unknown actions
        principal = Principal(user_id="u1", agent_id="a1")
        request = ActionRequest(
            principal=principal,
            action_name="completely_unknown",
            parameters={}
        )
        
        decision = engine.evaluate(request)
        assert decision.decision == DecisionType.BLOCK
        assert decision.reason_code == "NO_MATCHING_POLICY"
        # Should NOT list "default_deny" in matched policies
        assert "default_deny" not in decision.matched_policies
