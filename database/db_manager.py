"""
Database Helper Functions for SOC Agent
Provides simple interface for logging actions, threats, and isolations.
"""

import sqlite3
import json 
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

# Database path 
DB_PATH = Path(__file__).parent.parent / "soc_agent.db"

# CONNECTION HELPER

def get_connection():
    """Get database connection with row factory for dict-like access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# AUDIT LOG FUNCTIONS
def log_action(action_type: str, success: bool, user: str = "system", 
               device_name: str = None, details: Dict = None) -> int:
     
    """
    Log an action to the audit log.
    
    Args:
        action_type: Type of action (e.g., "law_query", "vm_isolation", "user_decision")
        success: Whether the action succeeded
        user: Username or "system"
        device_name: Target device (if applicable)
        details: Additional details as dictionary (will be JSON serialized)
    
    Returns:
        ID of inserted record
    """
    
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO audit_log (timestamp, action_type, user, device_name, success, details)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        datetime.now(timezone.utc).isoformat() + "Z",
        action_type,
        user,
        device_name,
        1 if success else 0,
        json.dumps(details) if details else None
    ))

    record_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return record_id

def log_law_query(table_name: str, device_name: str, record_count: int, 
                  time_range_hours: int, success: bool = True) -> int:
    """Log a Log Analytics Workspace query."""
    
    return log_action(
        action_type="law_query",
        success=success,
        device_name=device_name,
        details={
            "table_name": table_name,
            "record_count": record_count,
            "time_range_hours": time_range_hours
        }
    )

def log_user_decision(device_name: str, threat_title: str, decision: str, 
                      threat_confidence: str) -> int:
    """
    Log user's decision on an isolation request.
    
    Args:
        device_name: Device name
        threat_title: Title of the threat
        decision: "approved" or "declined"
        threat_confidence: Threat confidence level
    """
    
    return log_action(
        action_type="user_decision",
        success=True,
        device_name=device_name,
        details={
            "threat_title": threat_title,
            "decision": decision,
            "threat_confidence": threat_confidence
        }
    )

# THREAT HISTORY FUNCTIONS

def save_threat(threat: Dict, hunt_id: str = None, device_name: str = None, 
                table_name: str = None) -> int:
    """
    Save a discovered threat to the database.
    
    Args:
        threat: Threat dictionary from AI analysis
        hunt_id: Unique ID for this hunt session
        device_name: Device name being investigated
        table_name: Log Analytics table queried
    
    Returns:
        ID of inserted record
    """
    
    conn = get_connection()
    cursor = conn.cursor()
    
    mitre = threat.get('mitre', {})
    
    cursor.execute("""
        INSERT INTO threat_history (
            timestamp, hunt_id, threat_title, threat_description, confidence,
            mitre_tactic, mitre_technique, mitre_id, device_name, table_name,
            indicators_of_compromise, recommendations, log_lines
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now(timezone.utc).isoformat() + "Z",
        hunt_id,
        threat.get('title'),
        threat.get('description'),
        threat.get('confidence'),
        mitre.get('tactic'),
        mitre.get('technique'),
        mitre.get('id'),
        device_name,
        table_name,
        json.dumps(threat.get('indicators_of_compromise', [])),
        json.dumps(threat.get('recommendations', [])),
        json.dumps(threat.get('log_lines', []))
    ))
    
    record_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return record_id

def get_recent_threats(limit: int = 10, confidence: str = None) -> List[Dict]:
    """
    Get recent threats from database.
    
    Args:
        limit: Maximum number of threats to return
        confidence: Filter by confidence level (optional)
    
    Returns:
        List of threat dictionaries
    """
    
    conn = get_connection()
    cursor = conn.cursor()
    
    if confidence:
        cursor.execute("""
            SELECT * FROM threat_history 
            WHERE confidence = ?
            ORDER BY timestamp DESC 
            LIMIT ?
        """, (confidence, limit))
    else:
        cursor.execute("""
            SELECT * FROM threat_history 
            ORDER BY timestamp DESC 
            LIMIT ?
        """, (limit,))
    
    rows = cursor.fetchall()
    conn.close()

    threats = []
    for row in rows:
        threats.append({
            'id': row['id'],
            'timestamp': row['timestamp'],
            'threat_title': row['threat_title'],
            'threat_description': row['threat_description'],
            'confidence': row['confidence'],
            'device_name': row['device_name'],
            'mitre_tactic': row['mitre_tactic'],
            'mitre_technique': row['mitre_technique']
        })
    
    return threats

# ISOLATION EVENT FUNCTIONS

def log_isolation_event(machine_id: str, device_name: str, threat_id: str,
                        threat_title: str, action_result: str, 
                        user: str = "system", approved_by: str = None,
                        user_decision: str = None, alert_sent: bool = False) -> int:
    """
    Log a VM isolation event.
    
    Args:
        machine_id: MDE machine ID
        device_name: Device name
        threat_id: Threat identifier
        threat_title: Threat title
        action_result: "success", "failed", "declined"
        user: User who initiated
        approved_by: User who approved (if required)
        user_decision: "approved" or "declined"
        alert_sent: Whether alert was sent to SOC lead
    
    Returns:
        ID of inserted record
    """
    
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO isolation_events (
            timestamp, user, machine_id, device_name, threat_id, threat_title,
            action_result, approved_by, user_decision, alert_sent
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now(timezone.utc).isoformat() + "Z",
        user,
        machine_id,
        device_name,
        threat_id,
        threat_title,
        action_result,
        approved_by,
        user_decision,
        1 if alert_sent else 0
    ))
    
    record_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return record_id

def get_recent_isolations(minutes: int = 5, user: str = None) -> List[Dict]:
    """
    Get isolation events within the last N minutes.
    Used for rate limiting checks.
    
    Args:
        minutes: Time window in minutes
        user: Filter by specific user (optional)
    
    Returns:
        List of isolation event dictionaries
    """
    
    from datetime import timedelta
    
    conn = get_connection()
    cursor = conn.cursor()
    
    cutoff_time = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat() + "Z"
    
    if user:
        cursor.execute("""
            SELECT * FROM isolation_events 
            WHERE timestamp >= ? AND user = ?
            ORDER BY timestamp DESC
        """, (cutoff_time, user))
    else:
        cursor.execute("""
            SELECT * FROM isolation_events 
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
        """, (cutoff_time,))
    
    rows = cursor.fetchall()
    conn.close()
    
    events = []
    for row in rows:
        events.append({
            'id': row['id'],
            'timestamp': row['timestamp'],
            'user': row['user'],
            'device_name': row['device_name'],
            'action_result': row['action_result'],
            'threat_title': row['threat_title']
        })
    
    return events

def count_isolations_in_window(hours: int = None, minutes: int = None, 
                                user: str = None) -> int:
    """
    Count isolation events within a time window.
    
    Args:
        hours: Time window in hours (optional)
        minutes: Time window in minutes (optional)
        user: Filter by specific user (optional)
    
    Returns:
        Count of isolation events
    """
    
    from datetime import timedelta
    
    if hours:
        delta = timedelta(hours=hours)
    elif minutes:
        delta = timedelta(minutes=minutes)
    else:
        raise ValueError("Must specify either hours or minutes")
    
    conn = get_connection()
    cursor = conn.cursor()
    
    cutoff_time = (datetime.now(timezone.utc) - delta).isoformat() + "Z"
    
    if user:
        cursor.execute("""
            SELECT COUNT(*) FROM isolation_events 
            WHERE timestamp >= ? AND user = ? AND action_result = 'success'
        """, (cutoff_time, user))
    else:
        cursor.execute("""
            SELECT COUNT(*) FROM isolation_events 
            WHERE timestamp >= ? AND action_result = 'success'
        """, (cutoff_time,))
    
    count = cursor.fetchone()[0]
    conn.close()
    
    return count

#  UTILITY FUNCTIONS

def get_database_stats() -> Dict:
    """Get statistics about database contents."""
    
    conn = get_connection()
    cursor = conn.cursor()
    
    stats = {}
    
    # Audit log stats
    cursor.execute("SELECT COUNT(*) FROM audit_log")
    stats['total_audit_logs'] = cursor.fetchone()[0]
    
    # Threat history stats
    cursor.execute("SELECT COUNT(*) FROM threat_history")
    stats['total_threats'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT confidence, COUNT(*) FROM threat_history GROUP BY confidence")
    stats['threats_by_confidence'] = dict(cursor.fetchall())
    
    # Isolation event stats
    cursor.execute("SELECT COUNT(*) FROM isolation_events")
    stats['total_isolations'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT action_result, COUNT(*) FROM isolation_events GROUP BY action_result")
    stats['isolations_by_result'] = dict(cursor.fetchall())
    
    conn.close()
    
    return stats

if __name__ == "__main__":
    # Test database connection
    print("Testing database connection...")
    stats = get_database_stats()
    print(f"\n📊 Database Statistics:")
    print(f"  Total audit logs: {stats['total_audit_logs']}")
    print(f"  Total threats: {stats['total_threats']}")
    print(f"  Total isolations: {stats['total_isolations']}")

