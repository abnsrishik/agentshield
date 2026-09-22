"""Protected Tool Gateway - FastAPI service for mock enterprise APIs.

This gateway provides a service boundary between AgentShield and mock enterprise services.
It requires internal authentication for all requests.

SECURITY NOTE: This is an application-level prototype boundary. It prevents casual bypasses
by the AI agent but does NOT protect against a fully compromised host or malicious code
running with equivalent system privileges.
"""

import os
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel, Field

from .services import (
    transfer_money as banking_transfer,
    get_balance,
    send_email,
    get_customer,
    get_all_customers,
    search_customers,
    export_customer_data,
    reset_banking,
    reset_email,
    reset_customer_db,
)

# Internal authentication token (should be set via environment in production)
INTERNAL_AUTH_TOKEN = os.environ.get("AGENTSHIELD_GATEWAY_TOKEN", "gateway-secret-token-mvp")

app = FastAPI(title="AgentShield Protected Tool Gateway")


# Request/Response Models
class TransferRequest(BaseModel):
    amount: float = Field(gt=0)
    recipient: str
    account_number: str = Field(pattern=r"^\d{10}$")


class EmailRequest(BaseModel):
    to: str
    subject: str
    body: str


class CustomerSearchRequest(BaseModel):
    name_contains: str


class GatewayResponse(BaseModel):
    success: bool
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    request_id: Optional[str] = None


# Idempotency store (in-memory for MVP; use Redis/DB in production)
_idempotency_store: Dict[str, Dict] = {}


def verify_internal_auth(x_agentshield_auth: Optional[str] = Header(None, alias="X-AgentShield-Auth")) -> str:
    """Verify internal authentication token."""
    if not x_agentshield_auth:
        raise HTTPException(status_code=401, detail="Missing internal authentication token")
    
    if x_agentshield_auth != INTERNAL_AUTH_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid internal authentication token")
    
    return x_agentshield_auth


def check_idempotency(request_id: str, tool_name: str, params: Dict) -> Optional[Dict]:
    """Check if request was already processed (idempotency)."""
    if request_id in _idempotency_store:
        stored = _idempotency_store[request_id]
        # Verify the tool and params match (prevent replay with different params)
        if stored["tool"] == tool_name and stored["params_hash"] == hash(str(sorted(params.items()))):
            return stored["result"]
        else:
            raise HTTPException(
                status_code=409,
                detail="Request ID reused with different parameters"
            )
    return None


def store_idempotency(request_id: str, tool_name: str, params: Dict, result: Dict):
    """Store request for idempotency checking."""
    _idempotency_store[request_id] = {
        "tool": tool_name,
        "params_hash": hash(str(sorted(params.items()))),
        "result": result,
        "timestamp": datetime.now(timezone.utc)
    }


@app.post("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/tools/transfer_money", response_model=GatewayResponse)
async def execute_transfer(
    request: TransferRequest,
    request_id: str,
    auth_token: str = Depends(verify_internal_auth)
):
    """Execute money transfer (protected operation)."""
    # Check idempotency
    cached = check_idempotency(request_id, "transfer_money", request.model_dump())
    if cached:
        return GatewayResponse(success=True, result=cached, request_id=request_id)
    
    try:
        result = banking_transfer(
            amount=request.amount,
            recipient=request.recipient,
            account_number=request.account_number
        )
        
        # Store for idempotency
        store_idempotency(request_id, "transfer_money", request.model_dump(), result)
        
        return GatewayResponse(success=True, result=result, request_id=request_id)
    except ValueError as e:
        return GatewayResponse(success=False, error=str(e), request_id=request_id)
    except Exception as e:
        return GatewayResponse(success=False, error=f"Internal error: {str(e)}", request_id=request_id)


@app.post("/tools/send_email", response_model=GatewayResponse)
async def execute_send_email(
    request: EmailRequest,
    request_id: str,
    auth_token: str = Depends(verify_internal_auth)
):
    """Send email (protected operation)."""
    # Check idempotency
    cached = check_idempotency(request_id, "send_email", request.model_dump())
    if cached:
        return GatewayResponse(success=True, result=cached, request_id=request_id)
    
    try:
        result = send_email(
            to=request.to,
            subject=request.subject,
            body=request.body
        )
        
        store_idempotency(request_id, "send_email", request.model_dump(), result)
        
        return GatewayResponse(success=True, result=result, request_id=request_id)
    except Exception as e:
        return GatewayResponse(success=False, error=str(e), request_id=request_id)


@app.get("/tools/customer/{customer_id}", response_model=GatewayResponse)
async def get_customer_info(
    customer_id: str,
    auth_token: str = Depends(verify_internal_auth)
):
    """Get customer information (protected operation)."""
    request_id = f"get-customer-{customer_id}-{uuid.uuid4()}"
    
    try:
        customer = get_customer(customer_id)
        if not customer:
            return GatewayResponse(
                success=False,
                error=f"Customer {customer_id} not found",
                request_id=request_id
            )
        
        return GatewayResponse(success=True, result=customer, request_id=request_id)
    except Exception as e:
        return GatewayResponse(success=False, error=str(e), request_id=request_id)


@app.post("/tools/search_customers", response_model=GatewayResponse)
async def search_customers_endpoint(
    request: CustomerSearchRequest,
    request_id: str,
    auth_token: str = Depends(verify_internal_auth)
):
    """Search customers (protected operation)."""
    # Check idempotency
    cached = check_idempotency(request_id, "search_customers", request.model_dump())
    if cached:
        return GatewayResponse(success=True, result=cached, request_id=request_id)
    
    try:
        results = search_customers(request.name_contains)
        result = {"customers": results, "count": len(results)}
        
        store_idempotency(request_id, "search_customers", request.model_dump(), result)
        
        return GatewayResponse(success=True, result=result, request_id=request_id)
    except Exception as e:
        return GatewayResponse(success=False, error=str(e), request_id=request_id)


@app.get("/tools/export_customers", response_model=GatewayResponse)
async def export_customers_endpoint(
    auth_token: str = Depends(verify_internal_auth)
):
    """Export all customer data (highly restricted operation)."""
    request_id = f"export-customers-{uuid.uuid4()}"
    
    try:
        customers = export_customer_data()
        result = {"customers": customers, "count": len(customers)}
        
        return GatewayResponse(success=True, result=result, request_id=request_id)
    except Exception as e:
        return GatewayResponse(success=False, error=str(e), request_id=request_id)


@app.post("/admin/reset", response_model=GatewayResponse)
async def reset_services(
    auth_token: str = Depends(verify_internal_auth)
):
    """Reset all mock services (admin operation)."""
    try:
        reset_banking()
        reset_email()
        reset_customer_db()
        _idempotency_store.clear()
        
        return GatewayResponse(
            success=True,
            result={"message": "All mock services reset"},
            request_id=uuid.uuid4().hex
        )
    except Exception as e:
        return GatewayResponse(success=False, error=str(e), request_id=uuid.uuid4().hex)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)
