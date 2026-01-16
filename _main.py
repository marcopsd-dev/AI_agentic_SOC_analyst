# Standard library
import time
import sys
from pathlib import Path

# Third-party libraries
from colorama import Fore, init, Style
from openai import OpenAI
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient

# Local modules
import UTILITIES
import _keys
import MODEL_MANAGEMENT
import PROMPT_MANAGEMENT
import EXECUTOR
import GUARDRAILS

# Database and notifications
from database.db_manager import log_law_query, save_threat, log_isolation_event, log_user_decision
from notifications.alert_manager import alert_isolation_declined, alert_mass_isolation_decision


# STARTUP: Check if agent is locked


if GUARDRAILS.check_lockout():
    print(f"{Fore.RED}Exiting due to lockout.{Style.RESET_ALL}")
    exit(1)


# Initialize Azure and OpenAI Clients
#---------------------------------------------------------------------------

# Build the Log Analytics Client
law_client = LogsQueryClient(credential=DefaultAzureCredential())

# Build the OpenAI client
openai_client = OpenAI(api_key=_keys.OPENAI_API_KEY)

# Assign the default model
model = MODEL_MANAGEMENT.DEFAULT_MODEL


# Get user query and analyze


# Get the message from the user
user_message = PROMPT_MANAGEMENT.get_user_message()

# Get query context from AI
unformatted_query_context = EXECUTOR.get_query_context(openai_client, user_message, model=model)

# Sanitize query context
query_context = UTILITIES.sanitize_query_context(unformatted_query_context)

# Show the user where we are going to search
UTILITIES.display_query_context(query_context)

# Validate tables and fields
GUARDRAILS.validate_tables_and_fields(query_context["table_name"], query_context["fields"])


# Query Log Analytics Workspace
# ---------------------------------------------------------------------------

law_query_results = EXECUTOR.query_log_analytics(
    log_analytics_client=law_client,
    workspace_id=_keys.LOG_ANALYTICS_WORKSPACE_ID,
    timerange_hours=query_context["time_range_hours"],
    table_name=query_context["table_name"],
    device_name=query_context["device_name"],
    fields=query_context["fields"],
    caller=query_context["caller"],
    user_principal_name=query_context["user_principal_name"])

number_of_records = law_query_results['count']

print(f"{Fore.WHITE}{number_of_records} record(s) returned.\n")

# Log the query to database
log_law_query(
    table_name=query_context["table_name"],
    device_name=query_context.get("device_name", "multiple"),
    record_count=number_of_records,
    time_range_hours=query_context["time_range_hours"],
    success=True
)

# Exit if no records
if number_of_records == 0:
    print("Exiting.")
    exit(0)


# AI Threat Hunt
# ---------------------------------------------------------------------------

threat_hunt_user_message = PROMPT_MANAGEMENT.build_threat_hunt_prompt(
    user_prompt=user_message["content"],
    table_name=query_context["table_name"],
    log_data=law_query_results["records"]
)

threat_hunt_system_message = PROMPT_MANAGEMENT.SYSTEM_PROMPT_THREAT_HUNT
threat_hunt_messages = [threat_hunt_system_message, threat_hunt_user_message]

# Count tokens and select model
number_of_tokens = MODEL_MANAGEMENT.count_tokens(threat_hunt_messages, model)
model = MODEL_MANAGEMENT.choose_model(model, number_of_tokens)

# Validate model
GUARDRAILS.validate_model(model)
print(f"{Fore.LIGHTGREEN_EX}Initiating cognitive threat hunt against targeted logs...\n")

# Execute threat hunt
start_time = time.time()

hunt_results = EXECUTOR.hunt(
    openai_client=openai_client,
    threat_hunt_system_message=PROMPT_MANAGEMENT.SYSTEM_PROMPT_THREAT_HUNT,
    threat_hunt_user_message=threat_hunt_user_message,
    openai_model=model
)

if not hunt_results:
    exit()

elapsed = time.time() - start_time

print(f"{Fore.WHITE}Cognitive hunt complete. Took {elapsed:.2f} seconds and found {Fore.LIGHTRED_EX}{len(hunt_results['findings'])} {Fore.WHITE}potential threat(s)!\n")


# Check Batch Size

batch_check = GUARDRAILS.check_batch_size(len(hunt_results['findings']))
if not batch_check['allowed']:
    print(f"{Fore.RED}ERROR: {batch_check['reason']}{Style.RESET_ALL}")
    exit(1)

# Save threats to database 

import uuid
hunt_id = str(uuid.uuid4())[:8]  # Short unique ID for this hunt

for threat in hunt_results['findings']:
    save_threat(
        threat=threat,
        hunt_id=hunt_id,
        device_name=query_context.get("device_name"),
        table_name=query_context["table_name"]
    )


# Display Results


input(f"Press {Fore.LIGHTGREEN_EX}[Enter]{Fore.WHITE} or {Fore.LIGHTGREEN_EX}[Return]{Fore.WHITE} to see results.")

UTILITIES.display_threats(threat_list=hunt_results['findings'])


# Check for Mass Isolation Exception (NEW)


exception_data = GUARDRAILS.check_mass_isolation_exception(
    threats=hunt_results['findings'],
    device_name=query_context.get("device_name")
)

mass_isolation_approved = False

if exception_data['exception_applies']:
    print(f"\n{Fore.YELLOW}Mass isolation exception triggered: {exception_data['total_high_critical']} HIGH/CRITICAL threats detected{Style.RESET_ALL}\n")
    
    # Get user decision on mass isolation
    decision = GUARDRAILS.confirm_mass_isolation(exception_data)
    mass_isolation_approved = decision['approved']
    
    # Send alert to SOC lead
    alert_mass_isolation_decision(
        device_count=exception_data['total_devices'],
        threat_count=exception_data['total_high_critical'],
        decision="approved" if mass_isolation_approved else "denied",
        user="cli_user",
        threat_summary=exception_data['threat_summary']
    )
    
    # Log decision
    log_user_decision(
        device_name=query_context.get("device_name", "multiple"),
        threat_title=f"Mass isolation: {exception_data['total_high_critical']} threats",
        decision="approved" if mass_isolation_approved else "denied",
        threat_confidence="high/critical"
    )
    
    if not mass_isolation_approved:
        print(f"{Fore.YELLOW}Mass isolation declined. Exiting without isolating devices.{Style.RESET_ALL}")
        exit(0)


# Automated Response 

token = EXECUTOR.get_bearer_token()

query_is_about_individual_host = query_context["about_individual_host"]
query_is_about_individual_user = query_context["about_individual_user"]
query_is_about_network_security_group = query_context["about_network_security_group"]

machine_is_isolated = False
user_account_is_disabled = False

for threat in hunt_results['findings']:
    
    threat_confidence = threat["confidence"].lower()
    
    
    # HOST-RELATED THREATS
    
    
    if query_is_about_individual_host or mass_isolation_approved:
        
        # Skip if machine already isolated in this session
        if machine_is_isolated:
            continue
        
        # Check rate limits BEFORE any isolation attempt (NEW)
        rate_limit_check = GUARDRAILS.check_isolation_rate_limits(user="cli_user")
        
        if not rate_limit_check['allowed']:
            print(f"{Fore.RED}⛔ Cannot isolate: {rate_limit_check['reason']}{Style.RESET_ALL}")
            break  # Stop processing further threats
        
        # Apply confidence-based rules (NEW)
        should_ask_confirmation = GUARDRAILS.requires_confirmation(threat_confidence)
        can_auto_isolate = GUARDRAILS.should_auto_isolate(threat_confidence)
        
        # CRITICAL threats auto-isolate (NEW)
        if can_auto_isolate:
            print(f"\n{Fore.RED}🚨 CRITICAL threat detected - AUTO-ISOLATING:{Style.RESET_ALL}")
            print(f"{Fore.LIGHTRED_EX}{threat['title']}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Isolating {query_context['device_name']} automatically...{Style.RESET_ALL}\n")
            
            machine_id = EXECUTOR.get_mde_workstation_id_from_name(
                token=token,
                device_name=query_context["device_name"]
            )
            
            if machine_id:
                isolation_result = EXECUTOR.quarantine_virtual_machine(token=token, machine_id=machine_id)
                
                if isolation_result['success']:
                    machine_is_isolated = True
                    print(f"{Fore.GREEN}[+] VM successfully isolated.{Style.RESET_ALL}")
                    
                    # Log isolation
                    log_isolation_event(
                        machine_id=machine_id,
                        device_name=query_context["device_name"],
                        threat_id=hunt_id,
                        threat_title=threat['title'],
                        action_result="success",
                        user="cli_user",
                        user_decision="auto_approved"
                    )
                else:
                    print(f"{Fore.RED}[!] Isolation failed: {isolation_result.get('error')}{Style.RESET_ALL}")
                    
                    log_isolation_event(
                        machine_id=machine_id,
                        device_name=query_context["device_name"],
                        threat_id=hunt_id,
                        threat_title=threat['title'],
                        action_result="failed",
                        user="cli_user"
                    )
        
        # HIGH/MEDIUM threats require confirmation (NEW)
        elif should_ask_confirmation:
            print(f"\n{Fore.YELLOW}[!] {threat_confidence.upper()} confidence threat detected on host:{Style.RESET_ALL} {query_context['device_name']}")
            print(f"{Fore.LIGHTRED_EX}{threat['title']}{Style.RESET_ALL}")
            
            confirm = input(f"{Fore.RED}{Style.BRIGHT}Would you like to isolate this VM? (yes/no): {Style.RESET_ALL}").strip().lower()
            
            if confirm.startswith("y"):
                machine_id = EXECUTOR.get_mde_workstation_id_from_name(
                    token=token,
                    device_name=query_context["device_name"]
                )
                
                if machine_id:
                    isolation_result = EXECUTOR.quarantine_virtual_machine(token=token, machine_id=machine_id)
                    
                    if isolation_result['success']:
                        machine_is_isolated = True
                        print(f"{Fore.GREEN}[+] VM successfully isolated.{Style.RESET_ALL}")
                        
                        # Log isolation
                        log_isolation_event(
                            machine_id=machine_id,
                            device_name=query_context["device_name"],
                            threat_id=hunt_id,
                            threat_title=threat['title'],
                            action_result="success",
                            user="cli_user",
                            user_decision="approved"
                        )
                    else:
                        print(f"{Fore.RED}[!] Isolation failed: {isolation_result.get('error')}{Style.RESET_ALL}")
                        
                        log_isolation_event(
                            machine_id=machine_id,
                            device_name=query_context["device_name"],
                            threat_id=hunt_id,
                            threat_title=threat['title'],
                            action_result="failed",
                            user="cli_user",
                            user_decision="approved"
                        )
            else:
                print(f"{Fore.CYAN}[i] Isolation skipped by user.{Style.RESET_ALL}")
                
                # Send alert to SOC lead (NEW)
                alert_isolation_declined(
                    device_name=query_context["device_name"],
                    threat_title=threat['title'],
                    threat_confidence=threat_confidence,
                    user="cli_user"
                )
                
                # Log user decision
                log_user_decision(
                    device_name=query_context["device_name"],
                    threat_title=threat['title'],
                    decision="declined",
                    threat_confidence=threat_confidence
                )
        
        # LOW confidence - skip isolation
        else:
            print(f"{Fore.CYAN}[i] LOW confidence threat - skipping automatic isolation{Style.RESET_ALL}")
    
   
    # USER-RELATED THREATS 
    
    elif query_is_about_individual_user:
        print(f"{Fore.YELLOW}[i] User account workflow not yet implemented{Style.RESET_ALL}")
        pass
    
    
    # NSG-RELATED THREATS 
    
    elif query_is_about_network_security_group:
        print(f"{Fore.YELLOW}[i] NSG workflow not yet implemented{Style.RESET_ALL}")
        pass

print(f"\n{Fore.GREEN}✅ Threat hunt and response workflow complete!{Style.RESET_ALL}\n")