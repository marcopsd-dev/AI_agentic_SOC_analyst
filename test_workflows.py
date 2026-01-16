"""
Test script for SOC Agent workflows
Simulates threat scenarios without needing real Log Analytics data
"""

import sys
from pathlib import Path
from colorama import Fore, Style, init

init(autoreset=True)

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

import GUARDRAILS
from database.db_manager import log_isolation_event, log_user_decision
from notifications.alert_manager import alert_isolation_declined

# ============================================================================
# TEST 2: HIGH Confidence Threat Confirmation Workflow
# ============================================================================

def test_high_confidence_threat():
    """
    Simulate a HIGH confidence threat and test the confirmation workflow.
    """
    
    print("=" * 70)
    print("TEST 2: HIGH Confidence Threat - User Confirmation")
    print("=" * 70)
    print()
    
    # Simulate threat data
    device_name = "windows-test-target-1"
    threat = {
        'title': 'Suspicious Encoded PowerShell Command Execution',
        'confidence': 'high',
        'description': 'Detected base64-encoded PowerShell command execution',
        'indicators_of_compromise': ['powershell.exe', '-enc', 'suspicious_registry_key']
    }
    
    print(f"{Fore.CYAN}Simulated Threat:{Style.RESET_ALL}")
    print(f"  Device: {device_name}")
    print(f"  Title: {threat['title']}")
    print(f"  Confidence: {Fore.YELLOW}{threat['confidence'].upper()}{Style.RESET_ALL}")
    print()
    
    # Check if confirmation is required (should be True for HIGH)
    requires_confirmation = GUARDRAILS.requires_confirmation(threat['confidence'])
    print(f"Requires confirmation: {Fore.YELLOW if requires_confirmation else Fore.GREEN}{requires_confirmation}{Style.RESET_ALL}")
    print()
    
    if requires_confirmation:
        print(f"{Fore.YELLOW}[!] HIGH confidence threat detected on host:{Style.RESET_ALL} {device_name}")
        print(f"{Fore.LIGHTRED_EX}{threat['title']}{Style.RESET_ALL}")
        print()
        print(f"{Fore.CYAN}Testing Scenario 1: User APPROVES isolation{Style.RESET_ALL}")
        
        confirm = input(f"{Fore.RED}{Style.BRIGHT}Would you like to isolate this VM? (yes/no): {Style.RESET_ALL}").strip().lower()
        
        if confirm.startswith("y"):
            print(f"\n{Fore.GREEN}✅ User approved isolation{Style.RESET_ALL}")
            print(f"{Fore.CYAN}In real scenario, this would:{Style.RESET_ALL}")
            print(f"  1. Get machine ID from MDE")
            print(f"  2. Call isolation API")
            print(f"  3. Log isolation event to database")
            
            # Log the approved decision
            log_user_decision(
                device_name=device_name,
                threat_title=threat['title'],
                decision="approved",
                threat_confidence=threat['confidence']
            )
            print(f"\n{Fore.GREEN}✅ Logged approval decision to database{Style.RESET_ALL}")
            
        else:
            print(f"\n{Fore.YELLOW}⛔ User DECLINED isolation{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Triggering SOC lead alert...{Style.RESET_ALL}")
            
            # Send alert to SOC lead
            alert_sent = alert_isolation_declined(
                device_name=device_name,
                threat_title=threat['title'],
                threat_confidence=threat['confidence'],
                user="test_user"
            )
            
            if alert_sent:
                print(f"{Fore.GREEN}✅ Alert sent to SOC lead{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}⚠️  Alert not sent (email not configured){Style.RESET_ALL}")
            
            # Log the declined decision
            log_user_decision(
                device_name=device_name,
                threat_title=threat['title'],
                decision="declined",
                threat_confidence=threat['confidence']
            )
            print(f"{Fore.GREEN}✅ Logged declined decision to database{Style.RESET_ALL}")
    
    print()
    print(f"{Fore.GREEN}✅ Test 2 Complete{Style.RESET_ALL}")
    print()

# ============================================================================
# TEST 3: Rate Limit Validation
# ============================================================================

def test_rate_limiting():
    """
    Test rate limiting by simulating multiple isolation events.
    """
    
    print("=" * 70)
    print("TEST 3: Rate Limiting Validation")
    print("=" * 70)
    print()
    
    from database.db_manager import count_isolations_in_window
    from datetime import datetime, timezone
    
    # Show current isolation counts
    count_5min = count_isolations_in_window(minutes=5)
    count_1hour = count_isolations_in_window(hours=1)
    count_24hour = count_isolations_in_window(hours=24)
    
    print(f"{Fore.CYAN}Current Isolation Counts:{Style.RESET_ALL}")
    print(f"  Last 5 minutes: {count_5min}/{GUARDRAILS.ISOLATION_LIMITS['per_5_minutes']}")
    print(f"  Last hour: {count_1hour}/{GUARDRAILS.ISOLATION_LIMITS['per_hour']}")
    print(f"  Last 24 hours: {count_24hour}/{GUARDRAILS.ISOLATION_LIMITS['per_day']}")
    print()
    
    # Check current rate limit status
    print(f"{Fore.CYAN}Checking Rate Limits...{Style.RESET_ALL}")
    rate_check = GUARDRAILS.check_isolation_rate_limits(user="test_user")
    
    if rate_check['allowed']:
        print(f"{Fore.GREEN}✅ {rate_check['reason']}{Style.RESET_ALL}")
        print(f"   Current count in 5-min window: {rate_check['current_count']}")
    else:
        print(f"{Fore.RED}❌ {rate_check['reason']}{Style.RESET_ALL}")
    
    print()
    
    # Ask if user wants to simulate isolation events to test limits
    if rate_check['allowed'] and count_5min < 5:  # Only if well below limit
        print(f"{Fore.YELLOW}Would you like to simulate isolation events to test rate limiting?{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}This will add test records to the database.{Style.RESET_ALL}")
        
        simulate = input(f"Simulate isolation events? (yes/no): ").strip().lower()
        
        if simulate.startswith("y"):
            print()
            num_events = int(input(f"How many events to simulate (recommend 3-6): ").strip() or "3")
            
            print(f"\n{Fore.CYAN}Simulating {num_events} isolation events...{Style.RESET_ALL}")
            
            for i in range(num_events):
                log_isolation_event(
                    machine_id=f"test-machine-{i}",
                    device_name=f"windows-test-{i}",
                    threat_id=f"test-threat-{i}",
                    threat_title=f"Test Threat {i+1}",
                    action_result="success",
                    user="test_user",
                    user_decision="test_simulation"
                )
                print(f"  {Fore.GREEN}✅{Style.RESET_ALL} Logged isolation event {i+1}/{num_events}")
            
            print()
            
            # Check rate limits again
            rate_check_after = GUARDRAILS.check_isolation_rate_limits(user="test_user")
            count_after = count_isolations_in_window(minutes=5, user="test_user")
            
            print(f"{Fore.CYAN}Updated Isolation Counts:{Style.RESET_ALL}")
            print(f"  Last 5 minutes: {Fore.YELLOW}{count_after}/{GUARDRAILS.ISOLATION_LIMITS['per_5_minutes']}{Style.RESET_ALL}")
            print()
            
            if rate_check_after['allowed']:
                print(f"{Fore.GREEN}✅ Still within rate limits{Style.RESET_ALL}")
                if count_after >= 3:
                    print(f"{Fore.YELLOW}⚠️  Approaching limit - a few more isolations will trigger rate limiting{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}❌ RATE LIMIT EXCEEDED{Style.RESET_ALL}")
                print(f"{Fore.RED}   {rate_check_after['reason']}{Style.RESET_ALL}")
                print()
                print(f"{Fore.CYAN}Expected behavior:{Style.RESET_ALL}")
                print(f"  - Email alert sent to SOC lead")
                print(f"  - Further isolations blocked")
                print(f"  - Agent may be locked if significantly over limit")
    
    elif count_5min >= GUARDRAILS.ISOLATION_LIMITS['per_5_minutes']:
        print(f"{Fore.YELLOW}Rate limit already exceeded - cannot simulate more events{Style.RESET_ALL}")
        print(f"{Fore.CYAN}To reset for testing:{Style.RESET_ALL}")
        print(f"  1. Wait 5 minutes for window to clear")
        print(f"  2. Or delete test records from database")
    
    print()
    print(f"{Fore.GREEN}✅ Test 3 Complete{Style.RESET_ALL}")
    print()

# ============================================================================
# TEST 4: CRITICAL Auto-Isolation (Bonus Test)
# ============================================================================

def test_critical_auto_isolation():
    """
    Test CRITICAL threat auto-isolation (no confirmation required).
    """
    
    print("=" * 70)
    print("BONUS TEST: CRITICAL Threat Auto-Isolation")
    print("=" * 70)
    print()
    
    threat = {
        'title': 'Ransomware Encryption Activity Detected',
        'confidence': 'critical',
        'description': 'Active ransomware encryption in progress'
    }
    
    print(f"{Fore.CYAN}Simulated Threat:{Style.RESET_ALL}")
    print(f"  Title: {threat['title']}")
    print(f"  Confidence: {Fore.RED}{Style.BRIGHT}{threat['confidence'].upper()}{Style.RESET_ALL}")
    print()
    
    should_auto = GUARDRAILS.should_auto_isolate(threat['confidence'])
    requires_confirm = GUARDRAILS.requires_confirmation(threat['confidence'])
    
    print(f"Should auto-isolate: {Fore.GREEN if should_auto else Fore.RED}{should_auto}{Style.RESET_ALL}")
    print(f"Requires confirmation: {Fore.RED if requires_confirm else Fore.GREEN}{requires_confirm}{Style.RESET_ALL}")
    print()
    
    if should_auto:
        print(f"{Fore.RED}{Style.BRIGHT}🚨 CRITICAL threat - would AUTO-ISOLATE immediately{Style.RESET_ALL}")
        print(f"{Fore.CYAN}No user confirmation required for CRITICAL threats{Style.RESET_ALL}")
    
    print()
    print(f"{Fore.GREEN}✅ Bonus Test Complete{Style.RESET_ALL}")
    print()

# ============================================================================
# MAIN TEST MENU
# ============================================================================

def main():
    """Main test menu."""
    
    init()
    
    print()
    print(f"{Fore.CYAN}{Style.BRIGHT}SOC Agent Workflow Testing Suite{Style.RESET_ALL}")
    print()
    
    # Check lockout status first
    if GUARDRAILS.check_lockout():
        print(f"{Fore.RED}Agent is locked - cannot run tests{Style.RESET_ALL}")
        print(f"Delete .lock file to proceed")
        return
    
    print("Available Tests:")
    print("  2. HIGH Confidence Threat - User Confirmation & Email Alert")
    print("  3. Rate Limiting Validation")
    print("  4. CRITICAL Auto-Isolation (Bonus)")
    print("  5. Run All Tests")
    print()
    
    choice = input("Select test (2-5): ").strip()
    print()
    
    if choice == "2":
        test_high_confidence_threat()
    elif choice == "3":
        test_rate_limiting()
    elif choice == "4":
        test_critical_auto_isolation()
    elif choice == "5":
        test_high_confidence_threat()
        input(f"\n{Fore.CYAN}Press Enter to continue to Test 3...{Style.RESET_ALL}")
        print()
        test_rate_limiting()
        input(f"\n{Fore.CYAN}Press Enter to continue to Bonus Test...{Style.RESET_ALL}")
        print()
        test_critical_auto_isolation()
    else:
        print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")

if __name__ == "__main__":
    main()