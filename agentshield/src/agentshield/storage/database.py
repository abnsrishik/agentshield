"""
AgentShield SQLite Storage Layer.

Provides persistent storage for approvals and audit events.
Implements synchronous writes with fail-closed behavior.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager
from uuid import UUID

from ..core.models import ApprovalRequest, ApprovalStatus, AuditEvent, DecisionType
from ..core.exceptions import AuditLoggingError, ApprovalStorageError


class DatabaseManager:
    """Manages SQLite database connections and schema."""
    
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self._init_db()
    
    @contextmanager
    def get_connection(self):
        """Get a database connection with proper error handling."""
        conn = None
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            yield conn
        except sqlite3.Error as e:
            raise ApprovalStorageError(f"Database error: {e}") from e
        finally:
            if conn:
                conn.close()
    
    def _init_db(self):
        """Initialize database schema."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Create approvals table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    action_name TEXT NOT NULL,
                    parameters TEXT NOT NULL,
                    principal_snapshot TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    approver_id TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    decided_at TEXT,
                    used INTEGER NOT NULL DEFAULT 0
                )
            ''')
            
            # Create index on request_id for fast lookups
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_approvals_request_id 
                ON approvals(request_id)
            ''')
            
            # Create index on status for pending queries
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_approvals_status 
                ON approvals(status)
            ''')
            
            # Create audit_logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_logs (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    action_name TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    parameter_hash TEXT NOT NULL,
                    redacted_fields TEXT NOT NULL,
                    request_id TEXT,
                    approval_id TEXT
                )
            ''')
            
            # Create index on timestamp for querying
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp 
                ON audit_logs(timestamp)
            ''')
            
            conn.commit()


class ApprovalStore:
    """Persistent storage for approval requests."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def save_approval(self, approval: ApprovalRequest) -> None:
        """Save an approval request to the database."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO approvals 
                    (approval_id, request_id, request_hash, action_name, parameters,
                     principal_snapshot, status, approver_id, created_at, expires_at,
                     decided_at, used)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    str(approval.approval_id),
                    str(approval.request_id),
                    approval.request_hash,
                    approval.action_name,
                    json.dumps(approval.parameters),
                    json.dumps(approval.principal_snapshot),
                    approval.status.value,
                    approval.approver_id,
                    approval.created_at.isoformat(),
                    approval.expires_at.isoformat(),
                    approval.decided_at.isoformat() if approval.decided_at else None,
                    1 if approval.used else 0
                ))
                conn.commit()
            except sqlite3.Error as e:
                raise ApprovalStorageError(f"Failed to save approval: {e}") from e
    
    def get_approval(self, approval_id: UUID) -> Optional[ApprovalRequest]:
        """Retrieve an approval by ID."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM approvals WHERE approval_id = ?
            ''', (str(approval_id),))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            return self._row_to_approval(row)
    
    def get_approval_by_request_id(self, request_id: UUID) -> Optional[ApprovalRequest]:
        """Retrieve an approval by the original request ID."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM approvals WHERE request_id = ?
            ''', (str(request_id),))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            return self._row_to_approval(row)
    
    def update_approval_status(
        self, 
        approval_id: UUID, 
        status: ApprovalStatus,
        approver_id: Optional[str] = None,
        used: bool = False
    ) -> bool:
        """
        Update approval status atomically.
        
        Returns True if update succeeded, False if approval doesn't exist or can't be updated.
        Implements concurrency safety via database transaction.
        """
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            try:
                # Check current state before updating
                cursor.execute('''
                    SELECT status, used FROM approvals WHERE approval_id = ?
                ''', (str(approval_id),))
                
                row = cursor.fetchone()
                if not row:
                    return False
                
                current_status = row['status']
                current_used = bool(row['used'])
                
                # Prevent re-using an already used approval
                if current_used and not used:
                    return False
                
                # Only PENDING approvals can transition
                if current_status != 'PENDING' and status != ApprovalStatus.PENDING:
                    return False
                
                cursor.execute('''
                    UPDATE approvals 
                    SET status = ?, approver_id = ?, decided_at = ?, used = ?
                    WHERE approval_id = ?
                ''', (
                    status.value,
                    approver_id,
                    datetime.utcnow().isoformat(),
                    1 if used else 0,
                    str(approval_id)
                ))
                
                conn.commit()
                return cursor.rowcount > 0
                
            except sqlite3.Error:
                return False
    
    def mark_approval_used(self, approval_id: UUID) -> bool:
        """
        Mark an approval as used to prevent replay.
        
        Returns True if successful, False if approval doesn't exist or already used.
        """
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            try:
                # Atomic check-and-set
                cursor.execute('''
                    UPDATE approvals 
                    SET used = 1 
                    WHERE approval_id = ? AND used = 0
                ''', (str(approval_id),))
                
                conn.commit()
                return cursor.rowcount > 0
                
            except sqlite3.Error:
                return False
    
    def get_pending_approvals(self) -> List[ApprovalRequest]:
        """Get all pending approvals."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM approvals WHERE status = 'PENDING' ORDER BY created_at
            ''')
            
            return [self._row_to_approval(row) for row in cursor.fetchall()]
    
    def _row_to_approval(self, row: sqlite3.Row) -> ApprovalRequest:
        """Convert a database row to an ApprovalRequest object."""
        return ApprovalRequest(
            approval_id=UUID(row['approval_id']),
            request_id=UUID(row['request_id']),
            request_hash=row['request_hash'],
            action_name=row['action_name'],
            parameters=json.loads(row['parameters']),
            principal_snapshot=json.loads(row['principal_snapshot']),
            status=ApprovalStatus(row['status']),
            approver_id=row['approver_id'],
            created_at=datetime.fromisoformat(row['created_at']),
            expires_at=datetime.fromisoformat(row['expires_at']),
            decided_at=datetime.fromisoformat(row['decided_at']) if row['decided_at'] else None,
            used=bool(row['used'])
        )


class AuditStore:
    """Persistent storage for audit events."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def save_audit_event(self, event: AuditEvent) -> None:
        """
        Save an audit event synchronously.
        
        Raises AuditLoggingError on failure to support fail-closed behavior.
        """
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    INSERT INTO audit_logs 
                    (event_id, timestamp, user_id, agent_id, action_name, decision,
                     policy_version, parameter_hash, redacted_fields, request_id, approval_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    str(event.event_id),
                    event.timestamp.isoformat(),
                    event.user_id,
                    event.agent_id,
                    event.action_name,
                    event.decision.value,
                    event.policy_version,
                    event.parameter_hash,
                    json.dumps(event.redacted_fields),
                    str(event.request_id) if event.request_id else None,
                    str(event.approval_id) if event.approval_id else None
                ))
                conn.commit()
            except sqlite3.Error as e:
                raise AuditLoggingError(f"Failed to persist audit event: {e}") from e
    
    def get_audit_events(
        self, 
        limit: int = 100, 
        offset: int = 0
    ) -> List[AuditEvent]:
        """Retrieve audit events with pagination."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM audit_logs 
                ORDER BY timestamp DESC 
                LIMIT ? OFFSET ?
            ''', (limit, offset))
            
            return [self._row_to_event(row) for row in cursor.fetchall()]
    
    def _row_to_event(self, row: sqlite3.Row) -> AuditEvent:
        """Convert a database row to an AuditEvent object."""
        return AuditEvent(
            event_id=UUID(row['event_id']),
            timestamp=datetime.fromisoformat(row['timestamp']),
            user_id=row['user_id'],
            agent_id=row['agent_id'],
            action_name=row['action_name'],
            decision=DecisionType(row['decision']),
            policy_version=row['policy_version'],
            parameter_hash=row['parameter_hash'],
            redacted_fields=json.loads(row['redacted_fields']),
            request_id=UUID(row['request_id']) if row['request_id'] else None,
            approval_id=UUID(row['approval_id']) if row['approval_id'] else None
        )
