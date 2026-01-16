"""
Email Alert Manager for SOC Agent
Sends email notifications to SOC lead for security events.
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Optional
from colorama import Fore, Style
sys.path.insert(0, str(Path(__file__).parent.parent))
import _keys

def send_email_alert(subject: str, body: str, to_email: str ) -> bool: 
    """
   Send email alert to SOC lead.

   Args: 
         subject: Email subject
         body: Email body (plain text or HTML) 
         to_email: Recipient email (defaults to SOC_LEAD_EMAIL from config)

    Returns:
        True if sent successfully, False otherwise.
    """

    # Use default SOC lead email if not specified
    if not to_email:
        to_email = _keys.SOC_LEAD_EMAIL

    #Validate configuration 
    if not _keys.SMTP_USER or not _keys.SMTP_PASSWORD:
        print(f"{Fore.YELLOW}⚠️ Email not configured - alert not sent. {Style.RESET_ALL}")
        return False
    
    if not to_email: 
        print(f"{Fore.YELLOW}⚠️ No recipient email - alert not sent. {Style.RESET_ALL}")
        return False
    
    try:
        # Create message
        msg = MIMEMultipart('alternative')
        msg['subject'] = subject
        msg['From'] = _keys.ALERT_FROM_EMAIL or _keys.SMTP_USER
        msg['To'] = to_email
        msg['Date'] = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S %z")

        # Add body 
        msg.attach(MIMEText(body, 'plain'))

        # Connect and send 
        with smtplib.SMTP(_keys.SMTP_SERVER, _keys.SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(_keys.SMTP_USER, _keys.SMTP_PASSWORD)
            server.send_messgae(msg)

        print(f"{Fore.GREEN} ✅ Email alert sent to {to_email} {Style.RESET_ALL}")
        return True
    
    except Exception as e:
        print(f"{Fore.RED}❌ Failed to send email alert: {e} {Style.RESET_ALL}")
        return False

def alert_rate_limit_exceeded(isolation_count: int, time_window: str, device_name: str ) -> bool:

    """
    Alert when isolation rate limit is exceeded.
    
    Args:
        isolation_count: Number of isolations in the time window
        time_window: Description of time window (e.g., "5 minutes", "1 hour")
        device_name: Device name (if applicable)
    """

    subject = f"🚨 SOC Agent Alert: Rate Limit Exceeded ({isolation_count} isolations in {time_window})"

    body = f"""
SOC Agent Rate Limit Alert
===========================

Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
Event: Isolation rate limit exceeded

Details:
- Isolations: {isolation_count} in {time_window}
- Device: {device_name or 'Multiple devices'}
- Status: Agent activity paused pending review

Action Required:
The SOC Agent has paused isolation operations due to exceeding rate limits.
This could indicate:
1. Legitimate widespread security incident
2. Misconfigured detection rules
3. Potential compromise of agent or credentials

Please review recent isolation events and approve continuation if appropriate.

--
Automated alert from: Warne your AI SOC Threat Hunter.
"""

    return send_email_alert(subject, body)

def alert_isolation_declined(device_name: str, threat_title: str, 
                            threat_confidence: str, user: str = "system") -> bool:
    """
    Alert when user declines to isolate a high-confidence threat.
    
    Args:
        device_name: Device that was not isolated
        threat_title: Title of the threat
        threat_confidence: Threat confidence level
        user: User who declined
    """
    
    subject = f"⚠️  SOC Agent Alert: High-Confidence Threat Isolation Declined"
    
    body = f"""
SOC Agent Decision Alert
========================

Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
Event: User declined to isolate high-confidence threat

Details:
- Device: {device_name}
- Threat: {threat_title}
- Confidence: {threat_confidence}
- Decision by: {user}

Action Required:
A {threat_confidence.upper()} confidence threat was detected but isolation was declined.
Please review the threat assessment and ensure appropriate alternative actions are taken.

--
Automated alert from: Warne your AI SOC Threat Hunter.
"""
    
    return send_email_alert(subject, body)

def alert_mass_isolation_attempt(isolation_count: int, user: str = "system") -> bool:
    """
    Alert when potential mass isolation attack is detected.
    
    Args:
        isolation_count: Number of attempted isolations
        user: User who triggered the alert
    """
    
    subject = f"🚨 CRITICAL: Potential Mass Isolation Attack Detected"
    
    body = f"""
CRITICAL SECURITY ALERT
=======================

Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
Event: Mass isolation attempt detected

Details:
- Attempted isolations: {isolation_count}
- User/Session: {user}
- Status: Agent LOCKED - requires manual unlock

IMMEDIATE ACTION REQUIRED:
Warne has detected and blocked a potential mass isolation attack.
This could indicate:
1. Compromised user credentials
2. Malicious insider activity
3. Agent malfunction

The agent "{user}" has been automatically locked and will not perform further activities
until manually unlocked by an administrator.

To unlock: Delete the .lock file in the agent directory after investigation.

--
CRITICAL AUTOMATED ALERT from: Warne your AI SOC Threat Hunter.
"""
    
    return send_email_alert(subject, body)

def alert_daily_limit_reached(user: str = "system") -> bool:
    """
    Alert when daily isolation limit is reached and SOC lead approval needed.
    
    Args:
        user: User who reached the limit
    """
    
    subject = f"⚠️  SOC Agent: Daily Isolation Limit Reached - Approval Required"
    
    body = f"""
SOC Agent Limit Alert
=====================

Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
Event: Daily isolation limit reached (15 isolations)

Details:
- User/Session: {user}
- Daily limit: 15 isolations
- Status: SOC lead approval required for additional isolations

Action Required:
The SOC Agent has reached the daily isolation limit. Additional isolations
require SOC lead approval. 

If you approve additional isolations for today, please respond to this email
or contact the agent administrator.

--
Automated alert from: Warne your AI SOC Threat Hunter.
"""
    
    return send_email_alert(subject, body)

def alert_mass_isolation_decision(device_count: int, threat_count: int, 
                                  decision: str, user: str = "system",
                                  threat_summary: list = None) -> bool:
    """
    Alert SOC lead about mass isolation decision (approved or denied).
    
    Args:
        device_count: Number of devices involved
        threat_count: Number of threats detected
        decision: "approved" or "denied"
        user: User who made the decision
        threat_summary: List of threat titles/confidence levels
    
    Returns:
        True if alert sent successfully
    """
    
    decision_icon = "✅" if decision == "approved" else "⛔"
    decision_text = "APPROVED" if decision == "approved" else "DENIED"
    
    subject = f"{decision_icon} Mass Isolation {decision_text}: {device_count} devices"
    
    # Build threat summary section
    threat_details = ""
    if threat_summary:
        threat_details = "\n\nThreat Summary:\n" + "-" * 40 + "\n"
        for idx, threat in enumerate(threat_summary[:5], 1):  # Show first 5
            threat_details += f"{idx}. [{threat.get('confidence', 'UNKNOWN').upper()}] {threat.get('title', 'Unknown threat')}\n"
            threat_details += f"   Device: {threat.get('device_name', 'Unknown')}\n"
            threat_details += f"   IOCs: {', '.join(threat.get('iocs', ['None'])[:3])}\n\n"
        
        if len(threat_summary) > 5:
            threat_details += f"... and {len(threat_summary) - 5} more threats\n"
    
    body = f"""
SOC Agent Mass Isolation Decision
==================================

Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
Event: Mass isolation {'APPROVED' if decision == 'approved' else 'DENIED'} by analyst

Decision Summary:
- Devices affected: {device_count}
- Threats detected: {threat_count}
- Decision: {decision_text}
- Decided by: {user}
- Justification: Widespread HIGH/CRITICAL confidence threats detected
{threat_details}

{'Action Taken: All affected devices are being isolated' if decision == 'approved' else 'Action Taken: Mass isolation was declined - manual review required'}

{'Next Steps:\n- Monitor isolation status in Microsoft Defender\n- Investigate threat spread across environment\n- Prepare incident response procedures' if decision == 'approved' 
 else 'Next Steps:\n- Analyst has declined automatic mass isolation\n- Manual investigation and remediation required\n- Review threat assessment for false positives'}

--
Automated alert from: Warne your AI SOC Threat Hunter.
"""
    
    return send_email_alert(subject, body)

if __name__ == "__main__":

     # Test email configuration
    print("Testing email configuration...")

    if not _keys.SMTP_USER or not _keys.SMTP_PASSWORD:
        print(f"{Fore.YELLOW}⚠️  Email not configured in .env file{Style.RESET_ALL}")
        print("Please add SMTP settings to .env to enable email alerts")
    elif not _keys.SOC_LEAD_EMAIL:
        print(f"{Fore.YELLOW}⚠️  SOC_LEAD_EMAIL not set in .env file{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}✅ Email configuration found{Style.RESET_ALL}")
        print(f"SMTP Server: {_keys.SMTP_SERVER}:{_keys.SMTP_PORT}")
        print(f"From: {_keys.SMTP_USER}")
        print(f"To: {_keys.SOC_LEAD_EMAIL}")

        test = input(f"\n{Fore.CYAN}Send test email? (yes/no): {Style.RESET_ALL}").strip().lower()
        
        if test == "yes":
            success = send_email_alert(
                subject="🧪 SOC Agent Test Email",
                body="This is a test email from the Warne's SOC Agent alert system.\n\nIf you received this, email alerts are working correctly!"
            )
            if success:
                print(f"{Fore.GREEN}✅ Test email sent successfully!{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}❌ Test email failed{Style.RESET_ALL}")