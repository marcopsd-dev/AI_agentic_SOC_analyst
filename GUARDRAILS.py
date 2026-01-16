"""
Security Guardrails for SOC Agent
Implements rate limiting, confidence-based rules, and mass isolation prevention.
"""

import sys
from pathlib import Path
from datetime import datetime, timezone
from colorama import Fore, Style
sys.path.insert(0, str(Path(__file__).parent))
from database.db_manager import count_isolations_in_window, log_action
from notifications.alert_manager import (
    alert_rate_limit_exceeded,
    alert_mass_isolation_attempt,
    alert_daily_limit_reached
)

# ISOLATION RATE LIMITS (Based on User Requirements)


ISOLATION_LIMITS = {
    "per_5_minutes": 5,      # Max 5 isolations in 5 minutes
    "per_hour": 10,          # Max 10 isolations in 1 hour
    "per_day": 15,           # Max 15 isolations per day (SOC lead approval required for more)
    "batch_size_max": 50,    # Max threats to process in single hunt
    "high_threat_count_max": 10  # Alert if more than 10 HIGH/CRITICAL threats in one hunt
}


# CONFIDENCE-BASED ISOLATION RULES


CONFIDENCE_RULES = {
    "critical": "auto_isolate",           # CRITICAL auto-isolates
    "high": "require_confirmation",       # HIGH requires human confirmation
    "medium": "require_confirmation",     # MEDIUM requires human confirmation
    "low": "no_auto_isolate"             # LOW never auto-isolates
}


# ALLOWED TABLES AND FIELDS (Existing validation)


ALLOWED_TABLES = {
    "DeviceProcessEvents": { "TimeGenerated", "AccountName", "ActionType", "DeviceName", "InitiatingProcessCommandLine", "ProcessCommandLine" },
    "DeviceNetworkEvents": { "TimeGenerated", "ActionType", "DeviceName", "RemoteIP", "RemotePort" },
    "DeviceLogonEvents": { "TimeGenerated", "AccountName", "DeviceName", "ActionType", "RemoteIP", "RemoteDeviceName" },
    "AlertInfo": {},
    "AlertEvidence": {},
    "DeviceFileEvents": {"TimeGenerated","ActionType","DeviceName","FileName","FolderPath","InitiatingProcessAccountName","SHA256"},
    "DeviceRegistryEvents": {},
    "AzureNetworkAnalytics_CL": { "TimeGenerated", "FlowType_s", "SrcPublicIPs_s", "DestIP_s", "DestPort_d", "VM_s", "AllowedInFlows_d", "AllowedOutFlows_d", "DeniedInFlows_d", "DeniedOutFlows_d" },
    "AzureActivity": {"TimeGenerated", "OperationNameValue", "ActivityStatusValue", "ResourceGroup", "Caller", "CallerIpAddress", "Category" },
    "SigninLogs": {"TimeGenerated", "UserPrincipalName", "OperationName", "Category", "ResultSignature", "ResultDescription", "AppDisplayName", "IPAddress", "LocationDetails" },
}

# https://platform.openai.com/docs/models/compare
ALLOWED_MODELS = {
    "gpt-4.1-nano": {"max_input_tokens": 1_047_576, "max_output_tokens": 32_768,  "cost_per_million_input": 0.10, "cost_per_million_output": 0.40,  "tier": {"free": 40_000, "1": 200_000, "2": 2_000_000, "3": 4_000_000, "4": 10_000_000, "5": 150_000_000}},
    "gpt-4.1":      {"max_input_tokens": 1_047_576, "max_output_tokens": 32_768,  "cost_per_million_input": 1.00, "cost_per_million_output": 8.00,  "tier": {"free": None,   "1": 30_000,  "2": 450_000,   "3": 800_000,   "4": 2_000_000,  "5": 30_000_000}},
    "gpt-5-mini":   {"max_input_tokens": 272_000,   "max_output_tokens": 128_000, "cost_per_million_input": 0.25, "cost_per_million_output": 2.00,  "tier": {"free": None,   "1": 200_000, "2": 2_000_000, "3": 4_000_000, "4": 10_000_000, "5": 180_000_000}},
    "gpt-5":        {"max_input_tokens": 272_000,   "max_output_tokens": 128_000, "cost_per_million_input": 1.25, "cost_per_million_output": 10.00, "tier": {"free": None,   "1": 30_000,  "2": 450_000,   "3": 800_000,   "4": 2_000_000,  "5": 40_000_000}}
}


# LOCKOUT MECHANISM


LOCK_FILE = Path(__file__).parent / ".lock"

def check_lockout() -> bool:
    """
    Check if agent is locked due to suspicious activity.
    
    Returns:
        True if locked, False if operational
    """
    if LOCK_FILE.exists():
        print(f"{Fore.RED}{Style.BRIGHT}🔒 AGENT LOCKED{Style.RESET_ALL}")
        print(f"{Fore.RED}The SOC Agent has been locked due to suspicious activity.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Lock file: {LOCK_FILE}{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}To unlock:{Style.RESET_ALL}")
        print(f"1. Investigate recent isolation events")
        print(f"2. Delete the lock file: {LOCK_FILE}")
        print(f"3. Restart the agent\n")
        return True
    return False

def create_lockout(reason: str = "Mass isolation attempt detected") -> None:
    """
    Lock the agent and create lock file.
    
    Args:
        reason: Reason for lockout
    """
    try:
        LOCK_FILE.write_text(f"""
SOC Agent Locked
================
Time: {datetime.now(timezone.utc).isoformat()}
Reason: {reason}

To unlock:
1. Investigate the cause of this lockout
2. Review recent isolation events in the database
3. Delete this file to unlock the agent
4. Restart the agent

DO NOT unlock without proper investigation!
""")
        print(f"{Fore.RED}{Style.BRIGHT}🔒 AGENT LOCKED{Style.RESET_ALL}")
        print(f"{Fore.RED}Reason: {reason}{Style.RESET_ALL}")
        
        # Log to database
        log_action(
            action_type="agent_lockout",
            success=True,
            details={"reason": reason}
        )
        
    except Exception as e:
        print(f"{Fore.RED}Failed to create lock file: {e}{Style.RESET_ALL}")


# RATE LIMITING VALIDATION


def check_isolation_rate_limits(user: str = "system") -> dict:
    """
    Check if isolation rate limits are exceeded.
    
    Args:
        user: Username or "system"
    
    Returns:
        Dict with keys: allowed (bool), reason (str), current_count (int)
    """
    
    # Check for lockout first
    if check_lockout():
        return {
            "allowed": False,
            "reason": "Agent is locked",
            "current_count": 0
        }
    
    # Check 5-minute window
    count_5min = count_isolations_in_window(minutes=5, user=user)
    if count_5min >= ISOLATION_LIMITS["per_5_minutes"]:
        print(f"{Fore.RED}❌ Rate limit exceeded: {count_5min} isolations in last 5 minutes{Style.RESET_ALL}")
        alert_rate_limit_exceeded(count_5min, "5 minutes")
        
        # Lock agent if significantly over limit (potential attack)
        if count_5min > ISOLATION_LIMITS["per_5_minutes"] * 2:
            create_lockout(f"Excessive isolation rate: {count_5min} in 5 minutes")
            alert_mass_isolation_attempt(count_5min, user)
        
        return {
            "allowed": False,
            "reason": f"5-minute limit exceeded ({count_5min}/{ISOLATION_LIMITS['per_5_minutes']})",
            "current_count": count_5min
        }
    
    # Check 1-hour window
    count_1hour = count_isolations_in_window(hours=1, user=user)
    if count_1hour > ISOLATION_LIMITS["per_hour"]:
        print(f"{Fore.RED}❌ Rate limit exceeded: {count_1hour} isolations in last hour{Style.RESET_ALL}")
        alert_rate_limit_exceeded(count_1hour, "1 hour")
        return {
            "allowed": False,
            "reason": f"Hourly limit exceeded ({count_1hour}/{ISOLATION_LIMITS['per_hour']})",
            "current_count": count_1hour
        }
    
    # Check 24-hour window (daily limit)
    count_24hour = count_isolations_in_window(hours=24, user=user)
    if count_24hour > ISOLATION_LIMITS["per_day"]:
        print(f"{Fore.YELLOW}⚠️  Daily limit reached: {count_24hour} isolations in last 24 hours{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}SOC lead approval required for additional isolations{Style.RESET_ALL}")
        alert_daily_limit_reached(user)
        return {
            "allowed": False,
            "reason": f"Daily limit reached ({count_24hour}/{ISOLATION_LIMITS['per_day']}) - SOC lead approval required",
            "current_count": count_24hour
        }
    
    # All checks passed
    return {
        "allowed": True,
        "reason": "Within rate limits",
        "current_count": count_5min
    }

def check_batch_size(threat_count: int) -> dict:
    """
    Check if batch size is within limits.
    
    Args:
        threat_count: Number of threats found
    
    Returns:
        Dict with keys: allowed (bool), reason (str)
    """
    
    if threat_count > ISOLATION_LIMITS["batch_size_max"]:
        print(f"{Fore.RED}❌ Batch size exceeded: {threat_count} threats (max {ISOLATION_LIMITS['batch_size_max']}){Style.RESET_ALL}")
        return {
            "allowed": False,
            "reason": f"Too many threats in single hunt ({threat_count}). Narrow your search scope."
        }
    
    if threat_count > ISOLATION_LIMITS["high_threat_count_max"]:
        print(f"{Fore.YELLOW}⚠️  High threat count: {threat_count} threats detected{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}This may indicate a widespread incident - proceed with caution{Style.RESET_ALL}")
    
    return {
        "allowed": True,
        "reason": "Batch size acceptable"
    }

def check_mass_isolation_exception(threats: list, device_name: str = None) -> dict:
    """
    Check if mass isolation exception applies (10+ HIGH/CRITICAL threats).
    
    This exception allows mass isolation when a widespread security incident
    is detected, but requires explicit human approval.
    
    Args:
        threats: List of threat dictionaries from hunt results
        device_name: Primary device being investigated (if single-device query)
    
    Returns:
        Dict with keys:
            - exception_applies (bool): True if 10+ HIGH/CRITICAL threats
            - high_count (int): Number of HIGH confidence threats
            - critical_count (int): Number of CRITICAL confidence threats
            - total_devices (int): Number of unique devices affected
            - threat_summary (list): Summary of threats for display
    """
    
    # Count HIGH and CRITICAL threats
    high_threats = [t for t in threats if t.get('confidence', '').lower() == 'high']
    critical_threats = [t for t in threats if t.get('confidence', '').lower() == 'critical']
    
    high_count = len(high_threats)
    critical_count = len(critical_threats)
    total_high_critical = high_count + critical_count
    
    # Get unique device names from threats
    unique_devices = set()
    for threat in threats:
        # Device name might be in threat data or passed as parameter
        device = threat.get('device_name') or device_name
        if device:
            unique_devices.add(device)
    
    device_count = len(unique_devices)
    
    # Exception applies if 10+ HIGH/CRITICAL threats detected
    exception_applies = total_high_critical >= 10
    
    # Build summary for display
    threat_summary = []
    for threat in (critical_threats + high_threats)[:10]:  # First 10 threats
        threat_summary.append({
            'title': threat.get('title', 'Unknown threat'),
            'confidence': threat.get('confidence', 'unknown'),
            'device_name': threat.get('device_name') or device_name or 'Unknown',
            'iocs': threat.get('indicators_of_compromise', [])[:3]  # First 3 IOCs
        })
    
    return {
        'exception_applies': exception_applies,
        'high_count': high_count,
        'critical_count': critical_count,
        'total_high_critical': total_high_critical,
        'total_devices': device_count,
        'threat_summary': threat_summary
    }


def confirm_mass_isolation(exception_data: dict) -> dict:
    """
    Display mass isolation warning and get explicit user confirmation.
    
    Args:
        exception_data: Data from check_mass_isolation_exception()
    
    Returns:
        Dict with keys:
            - approved (bool): True if user approved
            - user_input (str): What user typed
            - timestamp (str): When decision was made
    """
    
    import time
    
    print(f"\n{Fore.RED}{Style.BRIGHT}{'=' * 70}{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}⚠️  MASS ISOLATION EXCEPTION TRIGGERED{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}{'=' * 70}{Style.RESET_ALL}\n")
    
    print(f"{Fore.YELLOW}A widespread security incident has been detected:{Style.RESET_ALL}\n")
    
    print(f"{Fore.WHITE}Threat Summary:{Style.RESET_ALL}")
    print(f"  • CRITICAL confidence threats: {Fore.RED}{exception_data['critical_count']}{Style.RESET_ALL}")
    print(f"  • HIGH confidence threats: {Fore.LIGHTYELLOW_EX}{exception_data['high_count']}{Style.RESET_ALL}")
    print(f"  • Total HIGH/CRITICAL: {Fore.LIGHTRED_EX}{exception_data['total_high_critical']}{Style.RESET_ALL}")
    print(f"  • Devices affected: {Fore.LIGHTRED_EX}{exception_data['total_devices']}{Style.RESET_ALL}\n")
    
    # Show first 3 threats in detail
    print(f"{Fore.CYAN}Sample Threats (first 3):{Style.RESET_ALL}")
    for idx, threat in enumerate(exception_data['threat_summary'][:3], 1):
        conf_color = Fore.RED if threat['confidence'].lower() == 'critical' else Fore.LIGHTYELLOW_EX
        print(f"\n  {idx}. [{conf_color}{threat['confidence'].upper()}{Style.RESET_ALL}] {threat['title']}")
        print(f"     Device: {threat['device_name']}")
        if threat['iocs']:
            print(f"     IOCs: {', '.join(str(ioc) for ioc in threat['iocs'][:2])}")
    
    if len(exception_data['threat_summary']) > 3:
        print(f"\n  ... and {len(exception_data['threat_summary']) - 3} more threats")
    
    print(f"\n{Fore.YELLOW}{'─' * 70}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}This appears to be a legitimate widespread security incident.{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Mass isolation can proceed with your explicit approval.{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'─' * 70}{Style.RESET_ALL}\n")
    
    print(f"{Fore.RED}WARNING: This will isolate {exception_data['total_high_critical']} machines from the network!{Style.RESET_ALL}\n")
    
    # 5-second countdown to prevent accidental approval
    print(f"{Fore.CYAN}Please review the above information carefully...{Style.RESET_ALL}")
    for i in range(5, 0, -1):
        print(f"{Fore.CYAN}Confirmation available in {i} second(s)...{Style.RESET_ALL}", end='\r')
        time.sleep(1)
    print(" " * 50)  # Clear the countdown line
    
    # Require explicit confirmation phrase
    print(f"\n{Fore.WHITE}To approve mass isolation, type exactly: {Fore.GREEN}{Style.BRIGHT}CONFIRM MASS ISOLATION{Style.RESET_ALL}")
    print(f"{Fore.WHITE}To decline, type anything else or press Enter{Style.RESET_ALL}\n")
    
    user_input = input(f"{Fore.YELLOW}Your decision: {Style.RESET_ALL}").strip()
    
    approved = user_input == "CONFIRM MASS ISOLATION"
    
    timestamp = datetime.now(timezone.utc).isoformat()
    
    if approved:
        print(f"\n{Fore.GREEN}✅ Mass isolation APPROVED{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Proceeding with isolation of {exception_data['total_high_critical']} devices...{Style.RESET_ALL}\n")
    else:
        print(f"\n{Fore.YELLOW}⛔ Mass isolation DECLINED{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}No devices will be isolated. Manual investigation required.{Style.RESET_ALL}\n")
    
    return {
        'approved': approved,
        'user_input': user_input,
        'timestamp': timestamp
    }

def should_auto_isolate(confidence: str) -> bool:
    """
    Determine if threat should auto-isolate based on confidence.
    
    Args:
        confidence: Threat confidence level (critical, high, medium, low)
    
    Returns:
        True if should auto-isolate without confirmation
    """
    
    confidence_lower = confidence.lower()
    rule = CONFIDENCE_RULES.get(confidence_lower, "require_confirmation")
    
    return rule == "auto_isolate"

def requires_confirmation(confidence: str) -> bool:
    """
    Determine if threat requires human confirmation before isolation.
    
    Args:
        confidence: Threat confidence level
    
    Returns:
        True if requires confirmation
    """
    
    confidence_lower = confidence.lower()
    rule = CONFIDENCE_RULES.get(confidence_lower, "require_confirmation")
    
    return rule == "require_confirmation"


# EXISTING VALIDATION FUNCTIONS (Unchanged)


def validate_tables_and_fields(table, fields):
    """Validate that table and fields are allowed."""
    
    print(f"{Fore.LIGHTGREEN_EX}Validating Tables and Fields...")
    if table not in ALLOWED_TABLES:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR: "f"Table '{table}' is not in allowed list – {Fore.RED}{Style.BRIGHT}{Style.RESET_ALL}exiting.")
        exit(1)
    
    fields = fields.replace(' ','').split(',')

    for field in fields:
        if field not in ALLOWED_TABLES[table]:
            print(f"{Fore.RED}{Style.BRIGHT}ERROR: Field '{field}' is not in allowed list for Table '{table}' – {Fore.RED}{Style.BRIGHT}{Style.RESET_ALL}exiting.")
            exit(1)
    
    print(f"{Fore.WHITE}Fields and tables have been validated and comply with the allowed guidelines.\n")

def validate_model(model):
    """Validate that model is allowed."""
    
    if model not in ALLOWED_MODELS:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR: Model '{model}' is not allowed – {Fore.RED}{Style.BRIGHT}{Style.RESET_ALL}exiting.")
        exit(1)
    else:
        print(f"{Fore.LIGHTGREEN_EX}Selected model is valid: {Fore.CYAN}{model}\n{Style.RESET_ALL}")


# TESTING / DEBUGGING


if __name__ == "__main__":
    print("=" * 60)
    print("SOC Agent Guardrails Test")
    print("=" * 60)
    
    print(f"\n{Fore.CYAN}Configuration:{Style.RESET_ALL}")
    print(f"5-minute limit: {ISOLATION_LIMITS['per_5_minutes']}")
    print(f"Hourly limit: {ISOLATION_LIMITS['per_hour']}")
    print(f"Daily limit: {ISOLATION_LIMITS['per_day']}")
    print(f"Batch size limit: {ISOLATION_LIMITS['batch_size_max']}")
    
    print(f"\n{Fore.CYAN}Confidence Rules:{Style.RESET_ALL}")
    for conf, rule in CONFIDENCE_RULES.items():
        print(f"  {conf.upper()}: {rule}")
    
    print(f"\n{Fore.CYAN}Lockout Status:{Style.RESET_ALL}")
    if check_lockout():
        print(f"  {Fore.RED}LOCKED{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}Operational{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}Rate Limit Check:{Style.RESET_ALL}")
    result = check_isolation_rate_limits()
    if result['allowed']:
        print(f"  {Fore.GREEN}✅ {result['reason']}{Style.RESET_ALL}")
    else:
        print(f"  {Fore.RED}❌ {result['reason']}{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}Testing Mass Isolation Exception:{Style.RESET_ALL}")

    # Simulate 12 HIGH/CRITICAL threats
    mock_threats = [
        {
            'title': f'Suspicious PowerShell Activity {i}',
            'confidence': 'critical' if i < 5 else 'high',
            'device_name': f'windows-target-{i}',
            'indicators_of_compromise': ['encoded_command.exe', 'suspicious_registry_key']
        }
        for i in range(1, 13)
    ]
    
    exception = check_mass_isolation_exception(mock_threats)
    
    if exception['exception_applies']:
        print(f"  {Fore.GREEN}✅ Exception triggered{Style.RESET_ALL}")
        print(f" MOCK THREATS: CRITICAL: {exception['critical_count']}, HIGH: {exception['high_count']}")
        
        # Uncomment to test confirmation flow:
        # decision = confirm_mass_isolation(exception)
        # print(f"  Decision: {'APPROVED' if decision['approved'] else 'DECLINED'}")
    else:
        print(f"  {Fore.YELLOW}⚠️  Exception not triggered (need 10+ HIGH/CRITICAL){Style.RESET_ALL}")