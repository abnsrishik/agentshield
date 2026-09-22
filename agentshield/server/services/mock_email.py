"""Mock Email Service for Protected Tool Gateway."""

from pydantic import BaseModel, Field
from typing import Optional


class EmailRequest(BaseModel):
    to: str = Field(min_length=1, description="Recipient email")
    subject: str = Field(min_length=1, description="Email subject")
    body: str = Field(min_length=1, description="Email body")
    from_domain: str = "company.com"


class EmailResponse(BaseModel):
    status: str
    message_id: str
    recipient: str


# In-memory mock state
_sent_emails = []


def send_email(to: str, subject: str, body: str, from_domain: str = "company.com") -> dict:
    """Send a mock email."""
    message_id = f"MSG-{len(_sent_emails) + 1}"
    
    _sent_emails.append({
        "message_id": message_id,
        "to": to,
        "subject": subject,
        "body": body,
        "from_domain": from_domain
    })
    
    return {
        "status": "sent",
        "message_id": message_id,
        "recipient": to
    }


def get_sent_emails() -> list:
    """Get list of sent emails (for testing)."""
    return _sent_emails.copy()


def reset_mock_data():
    """Reset mock data for testing."""
    global _sent_emails
    _sent_emails = []
