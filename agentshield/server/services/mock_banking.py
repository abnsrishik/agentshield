"""Mock Banking Service for Protected Tool Gateway."""

from pydantic import BaseModel, Field


class TransferRequest(BaseModel):
    amount: float = Field(gt=0, description="Transfer amount")
    recipient: str = Field(min_length=1, description="Recipient name")
    account_number: str = Field(pattern=r"^\d{10}$", description="10-digit account number")


class BalanceResponse(BaseModel):
    account: str
    balance: float
    currency: str = "INR"


# In-memory mock state
_mock_balances = {
    "1234567890": 100000.0,
    "0987654321": 50000.0,
}

_transfer_log = []


def transfer_money(amount: float, recipient: str, account_number: str) -> dict:
    """Execute a mock money transfer."""
    if account_number not in _mock_balances:
        raise ValueError(f"Account {account_number} not found")
    
    if _mock_balances[account_number] < amount:
        raise ValueError("Insufficient funds")
    
    _mock_balances[account_number] -= amount
    _transfer_log.append({
        "amount": amount,
        "recipient": recipient,
        "account_number": account_number
    })
    
    return {
        "status": "success",
        "transaction_id": f"TXN-{len(_transfer_log)}",
        "amount": amount,
        "recipient": recipient,
        "remaining_balance": _mock_balances[account_number]
    }


def get_balance(account_number: str) -> BalanceResponse:
    """Get mock account balance."""
    if account_number not in _mock_balances:
        raise ValueError(f"Account {account_number} not found")
    
    return BalanceResponse(
        account=account_number,
        balance=_mock_balances[account_number]
    )


def reset_mock_data():
    """Reset mock data for testing."""
    global _mock_balances, _transfer_log
    _mock_balances = {
        "1234567890": 100000.0,
        "0987654321": 50000.0,
    }
    _transfer_log = []
