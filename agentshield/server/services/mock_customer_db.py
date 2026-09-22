"""Mock Customer Database Service for Protected Tool Gateway."""

from typing import Dict, List, Optional


# In-memory mock customer data
_customers = {
    "C001": {"id": "C001", "name": "Alice Sharma", "email": "alice@company.com", "tier": "premium"},
    "C002": {"id": "C002", "name": "Bob Patel", "email": "bob@company.com", "tier": "standard"},
    "C003": {"id": "C003", "name": "Carol Singh", "email": "carol@external.com", "tier": "standard"},
}


def get_customer(customer_id: str) -> Optional[Dict]:
    """Get customer by ID."""
    return _customers.get(customer_id)


def get_all_customers() -> List[Dict]:
    """Get all customers (restricted operation)."""
    return list(_customers.values())


def search_customers(name_contains: str) -> List[Dict]:
    """Search customers by name."""
    return [
        c for c in _customers.values() 
        if name_contains.lower() in c["name"].lower()
    ]


def export_customer_data() -> List[Dict]:
    """Export all customer data (highly restricted operation)."""
    return list(_customers.values())


def reset_mock_data():
    """Reset mock data for testing."""
    global _customers
    _customers = {
        "C001": {"id": "C001", "name": "Alice Sharma", "email": "alice@company.com", "tier": "premium"},
        "C002": {"id": "C002", "name": "Bob Patel", "email": "bob@company.com", "tier": "standard"},
        "C003": {"id": "C003", "name": "Carol Singh", "email": "carol@external.com", "tier": "standard"},
    }
