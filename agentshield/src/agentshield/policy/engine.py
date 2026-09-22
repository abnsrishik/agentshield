"""
AgentShield Policy Engine.

Deterministic evaluation of YAML policies against action requests.
Implements BLOCK > REQUIRE_APPROVAL > ALLOW precedence.
Deny-by-default if no policy matches.
"""

import hashlib
import json
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.models import ActionRequest, PolicyDecision, DecisionType, Principal
from ..core.exceptions import PolicyEvaluationError


class PolicyCondition:
    """Represents a single condition in a policy rule."""
    
    SUPPORTED_OPERATORS = {
        'eq': lambda a, b: a == b,
        'neq': lambda a, b: a != b,
        'gt': lambda a, b: a > b if isinstance(a, (int, float)) else False,
        'gte': lambda a, b: a >= b if isinstance(a, (int, float)) else False,
        'lt': lambda a, b: a < b if isinstance(a, (int, float)) else False,
        'lte': lambda a, b: a <= b if isinstance(a, (int, float)) else False,
        'in': lambda a, b: a in b if isinstance(b, (list, tuple)) else False,
        'not_in': lambda a, b: a not in b if isinstance(b, (list, tuple)) else True,
        'exists': lambda a, b: a is not None,
    }

    def __init__(self, field: str, operator: str, value: Any = None):
        self.field = field
        self.operator = operator
        self.value = value
        
        if operator not in self.SUPPORTED_OPERATORS:
            raise ValueError(f"Unsupported operator: {operator}")

    def evaluate(self, data: Dict[str, Any]) -> bool:
        """Evaluate the condition against data."""
        # Navigate nested fields (e.g., "user.role")
        value = self._get_field_value(data, self.field)
        
        op_func = self.SUPPORTED_OPERATORS[self.operator]
        try:
            return op_func(value, self.value)
        except Exception:
            return False

    @staticmethod
    def _get_field_value(data: Dict[str, Any], field_path: str) -> Any:
        """Get value from nested dictionary using dot notation."""
        keys = field_path.split('.')
        current = data
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        
        return current


class PolicyRule:
    """Represents a single policy rule."""
    
    def __init__(self, rule_data: Dict[str, Any]):
        self.id = rule_data.get('id', 'unknown')
        self.description = rule_data.get('description', '')
        self.match_config = rule_data.get('match', {})
        self.consequence = rule_data.get('consequence', {})
        
        # Parse conditions
        self.conditions = []
        for cond in self.match_config.get('conditions', []):
            self.conditions.append(PolicyCondition(
                field=cond['field'],
                operator=cond['operator'],
                value=cond.get('value')
            ))
        
        # Parse action match
        self.action_match = self.match_config.get('action', '*')

    def matches_action(self, action_name: str) -> bool:
        """Check if rule applies to this action."""
        if self.action_match == '*':
            return True
        return self.action_match == action_name

    def matches_conditions(self, request_data: Dict[str, Any]) -> bool:
        """Check if all conditions are met."""
        for condition in self.conditions:
            if not condition.evaluate(request_data):
                return False
        return True

    def get_consequence(self) -> DecisionType:
        """Get the decision type from consequence."""
        cons_type = self.consequence.get('type', 'BLOCK')
        try:
            return DecisionType(cons_type)
        except ValueError:
            return DecisionType.BLOCK

    def get_approver_role(self) -> Optional[str]:
        """Get required approver role if applicable."""
        return self.consequence.get('approver_role')


class PolicyEngine:
    """
    Evaluates policies against action requests.
    Thread-safe, deterministic evaluation.
    """
    
    def __init__(self, policy_path: str):
        self.policy_path = Path(policy_path)
        self.rules: List[PolicyRule] = []
        self.policy_version: str = ""
        self._load_policies()

    def _load_policies(self):
        """Load and parse all YAML policy files."""
        self.rules = []
        all_rules_data = []
        
        if not self.policy_path.exists():
            raise PolicyEvaluationError(f"Policy path does not exist: {self.policy_path}")
        
        # Load all YAML files
        for yaml_file in self.policy_path.glob("*.yaml"):
            with open(yaml_file, 'r') as f:
                try:
                    data = yaml.safe_load(f)
                    if data and 'rules' in data:
                        all_rules_data.extend(data['rules'])
                except yaml.YAMLError as e:
                    raise PolicyEvaluationError(f"Failed to parse policy file {yaml_file}: {e}") from e
        
        # Parse rules
        for rule_data in all_rules_data:
            self.rules.append(PolicyRule(rule_data))
        
        # Generate policy version hash
        self.policy_version = self._compute_policy_hash(all_rules_data)

    def _compute_policy_hash(self, rules_data: List[Dict]) -> str:
        """Compute SHA-256 hash of canonical policy representation."""
        # Sort rules by ID for deterministic ordering
        sorted_rules = sorted(rules_data, key=lambda x: x.get('id', ''))
        canonical = json.dumps(sorted_rules, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def evaluate(self, request: ActionRequest) -> PolicyDecision:
        """
        Evaluate all matching policies and return a decision.
        
        Precedence: BLOCK > REQUIRE_APPROVAL > ALLOW
        Default: BLOCK (if no rules match)
        """
        # Prepare evaluation data
        eval_data = {
            'action': request.action_name,
            'amount': request.parameters.get('amount'),
            'user_id': request.principal.user_id,
            'agent_id': request.principal.agent_id,
            'roles': request.principal.roles,
            **request.parameters  # Flatten parameters for direct access
        }
        
        matched_policies = []
        decisions = []
        approver_role = None
        
        # Evaluate all rules (excluding default_deny which is implicit)
        for rule in self.rules:
            # Skip explicit default_deny rules - we handle deny-by-default implicitly
            if rule.id == 'default_deny':
                continue
                
            if not rule.matches_action(request.action_name):
                continue
                
            if rule.matches_conditions(eval_data):
                matched_policies.append(rule.id)
                consequence = rule.get_consequence()
                decisions.append(consequence)
                
                if consequence == DecisionType.REQUIRE_APPROVAL:
                    approver_role = rule.get_approver_role() or approver_role
        
        # Determine final decision based on precedence
        final_decision = self._resolve_precedence(decisions)
        
        # Generate response
        if final_decision == DecisionType.BLOCK:
            reason_code = "POLICY_BLOCK"
            message = "Action blocked by organizational policy"
        elif final_decision == DecisionType.REQUIRE_APPROVAL:
            reason_code = "REQUIRES_APPROVAL"
            message = "Action requires human approval before execution"
        elif final_decision == DecisionType.ALLOW:
            reason_code = "POLICY_ALLOW"
            message = "Action authorized by policy"
        else:
            # Default deny - no matching policies found
            final_decision = DecisionType.BLOCK
            reason_code = "NO_MATCHING_POLICY"
            message = "No policy explicitly authorizes this action (Deny-by-Default)"
        
        return PolicyDecision(
            decision=final_decision,
            reason_code=reason_code,
            message=message,
            matched_policies=matched_policies,
            policy_version=self.policy_version,
            required_approver_role=approver_role
        )

    @staticmethod
    def _resolve_precedence(decisions: List[DecisionType]) -> DecisionType:
        """
        Resolve multiple decisions using precedence:
        BLOCK > REQUIRE_APPROVAL > ALLOW
        """
        if not decisions:
            return None  # Will trigger default deny
        
        if DecisionType.BLOCK in decisions:
            return DecisionType.BLOCK
        
        if DecisionType.REQUIRE_APPROVAL in decisions:
            return DecisionType.REQUIRE_APPROVAL
        
        if DecisionType.ALLOW in decisions:
            return DecisionType.ALLOW
        
        return None
