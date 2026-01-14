"""
Secure configuration management using environment variables.
Secrets are loaded from .env file and never hardcoded.
"""

import os
from dotenv import load_dotenv
from colorama import Fore, Style

# Load environment variables from .env file
load_dotenv()


# CRITICAL SECRETS - Must be set in .env file


OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
LOG_ANALYTICS_WORKSPACE_ID = os.getenv('LOG_ANALYTICS_WORKSPACE_ID')


# EMAIL CONFIGURATION (for future alert phases)


SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.office365.com')
smtp_port_str = os.getenv('SMTP_PORT', '587')
SMTP_PORT = int(smtp_port_str) if smtp_port_str and smtp_port_str.strip() else 587
SMTP_USER = os.getenv('SMTP_USER', '')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')
SOC_LEAD_EMAIL = os.getenv('SOC_LEAD_EMAIL', '')


# APPLICATION SETTINGS

SOC_AGENT_MODE = os.getenv('SOC_AGENT_MODE', 'desktop')  # desktop, server, container
DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'


# VALIDATION - Ensure critical secrets are present

def validate_configuration():
    """
    Validate that all required configuration is present.
    Called on import to fail fast if secrets are missing.
    """
    errors = []
    
    if not OPENAI_API_KEY:
        errors.append("OPENAI_API_KEY is not set")
    elif OPENAI_API_KEY == "your-actual-openai-key-here":
        errors.append("OPENAI_API_KEY still has placeholder value")
    
    if not LOG_ANALYTICS_WORKSPACE_ID:
        errors.append("LOG_ANALYTICS_WORKSPACE_ID is not set")
    elif LOG_ANALYTICS_WORKSPACE_ID == "your-workspace-id-here":
        errors.append("LOG_ANALYTICS_WORKSPACE_ID still has placeholder value")
    
    if errors:
        print(f"{Fore.RED}{Style.BRIGHT}❌ CONFIGURATION ERROR:{Style.RESET_ALL}")
        print(f"{Fore.RED}The following required environment variables are missing or invalid:{Style.RESET_ALL}\n")
        for error in errors:
            print(f"  • {error}")
        print(f"\n{Fore.YELLOW}Please ensure you have:{Style.RESET_ALL}")
        print(f"  1. Created a .env file in the project root")
        print(f"  2. Copied values from .env.example")
        print(f"  3. Replaced placeholder values with your actual credentials")
        print(f"\n{Fore.CYAN}Example .env file location:{Style.RESET_ALL}")
        print(f"  {os.path.join(os.getcwd(), '.env')}")
        raise ValueError("Configuration validation failed. See errors above.")

# Validate configuration on module import
validate_configuration()

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_config_summary():
    """Return a safe summary of current configuration (no secrets exposed)."""
    return {
        'openai_key_configured': bool(OPENAI_API_KEY and OPENAI_API_KEY != "your-actual-openai-key-here"),
        'workspace_id_configured': bool(LOG_ANALYTICS_WORKSPACE_ID and LOG_ANALYTICS_WORKSPACE_ID != "your-workspace-id-here"),
        'smtp_configured': bool(SMTP_USER and SMTP_PASSWORD),
        'soc_lead_email_configured': bool(SOC_LEAD_EMAIL),
        'mode': SOC_AGENT_MODE,
        'debug': DEBUG
    }

def print_config_status():
    """Print configuration status for troubleshooting."""
    config = get_config_summary()
    
    print(f"{Fore.CYAN}Configuration Status:{Style.RESET_ALL}")
    print(f"  OpenAI Key:      {'✅ Configured' if config['openai_key_configured'] else '❌ Missing'}")
    print(f"  Workspace ID:    {'✅ Configured' if config['workspace_id_configured'] else '❌ Missing'}")
    print(f"  Email Alerts:    {'✅ Configured' if config['smtp_configured'] else '⚠️  Not configured (optional)'}")
    print(f"  SOC Lead Email:  {'✅ Configured' if config['soc_lead_email_configured'] else '⚠️  Not configured (optional)'}")
    print(f"  Mode:            {config['mode']}")
    print(f"  Debug:           {config['debug']}")
    print()

if __name__ == "__main__":
    # Allow testing configuration by running this file directly
    print_config_status()