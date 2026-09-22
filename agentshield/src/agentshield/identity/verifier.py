"""
AgentShield Identity Verifier.

Handles JWT verification and creates trusted Principal objects.
Separates Authentication (Who?) from Authorization (What allowed?).
"""

import jwt
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from ..core.models import Principal
from ..core.exceptions import IdentityVerificationError


class IdentityVerifier:
    """
    Verifies authentication tokens and extracts trusted identity.
    """

    def __init__(self, secret_key: str, algorithm: str = "HS256"):
        self.secret_key = secret_key
        self.algorithm = algorithm

    def verify_token(self, token: str) -> Principal:
        """
        Verify a JWT token and return a trusted Principal.
        
        Args:
            token: The JWT token string.
            
        Returns:
            Principal: A trusted identity object.
            
        Raises:
            IdentityVerificationError: If token is invalid or expired.
        """
        try:
            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=[self.algorithm],
                options={"require": ["exp", "user_id", "agent_id"]}
            )
            
            # Extract trusted fields - never pass the raw token
            user_id = payload.get("user_id")
            agent_id = payload.get("agent_id")
            roles = payload.get("roles", [])
            
            if not user_id or not agent_id:
                raise IdentityVerificationError(
                    reason_code="MISSING_CLAIMS",
                    message="Token missing required claims: user_id, agent_id"
                )
            
            # Create immutable Principal object
            return Principal(
                user_id=user_id,
                roles=roles if isinstance(roles, list) else [roles],
                agent_id=agent_id,
                auth_context={
                    "issued_at": payload.get("iat"),
                    "expires_at": payload.get("exp"),
                    "auth_method": "jwt"
                }
            )
            
        except jwt.ExpiredSignatureError as e:
            raise IdentityVerificationError(
                reason_code="TOKEN_EXPIRED",
                message="Authentication token has expired"
            ) from e
        except jwt.InvalidTokenError as e:
            raise IdentityVerificationError(
                reason_code="INVALID_TOKEN",
                message=f"Invalid authentication token: {str(e)}"
            ) from e
        except Exception as e:
            if isinstance(e, IdentityVerificationError):
                raise
            raise IdentityVerificationError(
                reason_code="VERIFICATION_FAILED",
                message="Identity verification failed"
            ) from e

    @staticmethod
    def create_test_token(
        user_id: str, 
        agent_id: str, 
        secret_key: str, 
        roles: list = None,
        expire_minutes: int = 60
    ) -> str:
        """
        Helper to create a test token. 
        In production, use a real auth server.
        """
        now = datetime.utcnow()
        payload = {
            "user_id": user_id,
            "agent_id": agent_id,
            "roles": roles or ["employee"],
            "iat": now,
            "exp": now + timedelta(minutes=expire_minutes)
        }
        return jwt.encode(payload, secret_key, algorithm="HS256")
