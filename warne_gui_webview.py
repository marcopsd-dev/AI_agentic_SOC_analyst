"""
Warne AI SOC Agent - HTML GUI Integration
Uses pywebview to embed the HTML/CSS/JavaScript interface
This maintains the exact design from the HTML version
"""

import webview
import threading
import json
from typing import Callable, Optional, Dict, List


class WarneGUI:
    """
    Main GUI class that embeds HTML/CSS/JavaScript interface
    Maintains exact design from HTML prototype
    """
    
    def __init__(self, on_send_message: Optional[Callable] = None):
        """
        Initialize Warne GUI with HTML interface
        
        Args:
            on_send_message: Callback function when user sends a message
                           Should accept (message: str) -> str (response)
        """
        self.on_send_message = on_send_message
        self.window = None
        self.api = None
        
    def _get_html_content(self):
        """Return the complete HTML/CSS/JS for the interface"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Warne AI - SOC Agent</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #e8e9eb 0%, #d9dade 50%, #e2e4e6 100%);
            background-size: 200% 200%;
            animation: gentleGradient 20s ease infinite;
            height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }
        
        @keyframes gentleGradient {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        
        .header {
            background: rgba(255, 255, 255, 0.4);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border-bottom: 1px solid rgba(140, 140, 140, 0.15);
            padding: 18px 28px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            z-index: 100;
            position: relative;
        }
        
        .header-left { display: flex; align-items: center; gap: 14px; }
        
        .logo {
            width: 38px;
            height: 38px;
            background: rgba(255, 255, 255, 0.5);
            backdrop-filter: blur(10px);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            border: 1px solid rgba(140, 140, 140, 0.2);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
            padding: 4px;
        }
        
        .logo svg { width: 100%; height: 100%; }
        
        .title-container { display: flex; flex-direction: column; gap: 2px; }
        
        .title {
            font-size: 18px;
            font-weight: 700;
            color: #3d3d3d;
            letter-spacing: -0.5px;
        }
        
        .subtitle {
            font-size: 11px;
            font-weight: 500;
            color: #7a7a7a;
            letter-spacing: 1.2px;
            text-transform: uppercase;
        }
        
        .status-container {
            display: flex;
            align-items: center;
            gap: 8px;
            background: rgba(255, 255, 255, 0.35);
            padding: 6px 14px;
            border-radius: 20px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(140, 140, 140, 0.15);
        }
        
        .status-dot {
            width: 8px;
            height: 8px;
            background: #7db88e;
            border-radius: 50%;
            box-shadow: 0 0 8px rgba(125, 184, 142, 0.5);
        }
        
        .status-text { font-size: 12px; font-weight: 500; color: #5a5a5a; }
        
        .main-container {
            flex: 1;
            display: flex;
            padding: 24px;
            gap: 20px;
            overflow: hidden;
            position: relative;
        }
        
        .sidebar {
            width: 300px;
            display: flex;
            flex-direction: column;
            gap: 16px;
            overflow: visible;
            transition: transform 0.4s cubic-bezier(0.4, 0, 0.2, 1), opacity 0.4s ease;
        }
        
        .sidebar.hidden {
            transform: translateX(-340px);
            opacity: 0;
            pointer-events: none;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.45);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border-radius: 20px;
            padding: 22px;
            border: 1px solid rgba(140, 140, 140, 0.2);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.06);
            display: flex;
            flex-direction: column;
            flex: 1;
        }
        
        .card-title {
            font-size: 11px;
            font-weight: 600;
            color: #6b6b6b;
            margin-bottom: 16px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
        }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            flex: 1;
            align-content: start;
        }
        
        .metric-box {
            background: rgba(255, 255, 255, 0.6);
            border-radius: 14px;
            padding: 16px;
            text-align: center;
            border: 1px solid rgba(140, 140, 140, 0.15);
        }
        
        .metric-value {
            font-size: 28px;
            font-weight: 700;
            color: #3d3d3d;
            margin-bottom: 4px;
        }
        
        .metric-label {
            font-size: 11px;
            color: #7a7a7a;
            font-weight: 500;
        }
        
        .threat-list {
            display: flex;
            flex-direction: column;
            gap: 10px;
            overflow-y: auto;
            padding-right: 4px;
            flex: 1;
        }
        
        .threat-item {
            background: rgba(255, 255, 255, 0.6);
            border-radius: 14px;
            padding: 14px;
            border: 1px solid rgba(140, 140, 140, 0.15);
            display: flex;
            gap: 12px;
            align-items: flex-start;
        }
        
        .threat-icon {
            width: 36px;
            height: 36px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 16px;
            flex-shrink: 0;
        }
        
        .threat-icon.high { background: linear-gradient(135deg, #d9a6a3 0%, #c99592 100%); }
        .threat-icon.medium { background: linear-gradient(135deg, #d9c3a3 0%, #c9b392 100%); }
        .threat-icon.low { background: linear-gradient(135deg, #bdd9a3 0%, #adc992 100%); }
        
        .threat-content { flex: 1; }
        
        .threat-title {
            font-size: 13px;
            font-weight: 600;
            color: #3d3d3d;
            margin-bottom: 3px;
        }
        
        .threat-meta { font-size: 11px; color: #8a8a8a; }
        
        .chat-section {
            flex: 1;
            display: flex;
            flex-direction: column;
            gap: 16px;
            position: relative;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        .chat-section.expanded {
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            padding: 0;
            gap: 0;
        }
        
        .chat-window {
            flex: 1;
            background: rgba(255, 255, 255, 0.45);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border-radius: 24px;
            padding: 28px;
            border: 1px solid rgba(140, 140, 140, 0.2);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.06);
            display: flex;
            flex-direction: column;
            gap: 18px;
            position: relative;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        .chat-section.expanded .chat-window {
            border-radius: 0;
            padding: 32px 48px;
            height: calc(100% - 76px);
        }
        
        .expand-button {
            position: absolute;
            top: 16px;
            left: 16px;
            width: 24px;
            height: 24px;
            background: rgba(255, 255, 255, 0.45);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(140, 140, 140, 0.2);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
            z-index: 10;
        }
        
        .expand-button:hover {
            background: rgba(140, 140, 140, 0.3);
            border-color: rgba(100, 100, 100, 0.35);
            transform: scale(1.1);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        }
        
        .expand-button svg {
            width: 12px;
            height: 12px;
            transition: transform 0.3s ease;
        }
        
        .expand-button.expanded svg { transform: rotate(180deg); }
        
        .chat-messages {
            flex: 1;
            overflow-y: auto;
            padding-right: 8px;
            padding-left: 44px;
        }
        
        .chat-section.expanded .chat-messages {
            padding-right: 12px;
            padding-left: 0;
        }
        
        .chat-messages::-webkit-scrollbar { width: 6px; }
        .chat-messages::-webkit-scrollbar-track { 
            background: rgba(200, 200, 200, 0.2); 
            border-radius: 10px;
            margin: 8px 0;
        }
        .chat-messages::-webkit-scrollbar-thumb { 
            background: rgba(120, 120, 120, 0.3); 
            border-radius: 10px; 
        }
        .chat-messages::-webkit-scrollbar-thumb:hover { 
            background: rgba(100, 100, 100, 0.5); 
        }
        
        .chat-section.expanded .chat-messages::-webkit-scrollbar { width: 8px; }
        
        .message-container { display: flex; flex-direction: column; gap: 18px; }
        
        .message { display: flex; gap: 12px; align-items: flex-start; }
        .message.user { flex-direction: row-reverse; }
        
        .avatar {
            width: 36px;
            height: 36px;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.7);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 14px;
            color: #5a5a5a;
            flex-shrink: 0;
            border: 2px solid rgba(140, 140, 140, 0.25);
        }
        
        .message-bubble {
            background: rgba(255, 255, 255, 0.85);
            padding: 16px 18px;
            border-radius: 18px;
            max-width: 65%;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.04);
            border: 1px solid rgba(140, 140, 140, 0.2);
        }
        
        .message.user .message-bubble {
            background: rgba(180, 180, 180, 0.25);
            border: 1px solid rgba(140, 140, 140, 0.3);
        }
        
        .message-text {
            font-size: 14px;
            line-height: 1.6;
            color: #3d3d3d;
            white-space: pre-wrap;
        }
        
        .alert-badge {
            background: rgba(217, 166, 163, 0.4);
            border-left: 3px solid #c99592;
            padding: 12px;
            margin-top: 10px;
            border-radius: 10px;
            backdrop-filter: blur(10px);
        }
        
        .alert-title {
            font-size: 11px;
            font-weight: 700;
            color: #a87370;
            margin-bottom: 4px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .alert-text {
            font-size: 13px;
            color: #4a4a4a;
            line-height: 1.4;
        }
        
        .input-area {
            background: rgba(255, 255, 255, 0.45);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border-radius: 24px;
            padding: 16px 20px;
            border: 1px solid rgba(140, 140, 140, 0.2);
            display: flex;
            align-items: center;
            gap: 14px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.04);
            position: relative;
            z-index: 60;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        .chat-section.expanded .input-area { border-radius: 0; margin: 0; }
        
        .input-field {
            flex: 1;
            background: transparent;
            border: none;
            outline: none;
            font-size: 14px;
            color: #3d3d3d;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        }
        
        .input-field::placeholder { color: #9a9a9a; }
        
        .send-button {
            width: 40px;
            height: 40px;
            background: rgba(140, 140, 140, 0.25);
            border: 1px solid rgba(120, 120, 120, 0.3);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all 0.3s ease;
            backdrop-filter: blur(10px);
        }
        
        .send-button:hover {
            background: rgba(120, 120, 120, 0.4);
            transform: scale(1.05);
        }
        
        .send-button::after {
            content: '→';
            font-size: 18px;
            color: #5a5a5a;
            font-weight: 700;
        }
        
        .threat-list::-webkit-scrollbar { width: 6px; }
        .threat-list::-webkit-scrollbar-track { 
            background: rgba(200, 200, 200, 0.2); 
            border-radius: 10px;
        }
        .threat-list::-webkit-scrollbar-thumb { 
            background: rgba(120, 120, 120, 0.3); 
            border-radius: 10px; 
        }
        .threat-list::-webkit-scrollbar-thumb:hover { 
            background: rgba(100, 100, 100, 0.5); 
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-left">
            <div class="logo">
                <svg viewBox="0 0 100 100" fill="none">
                    <path d="M50 15 L75 25 L75 50 C75 65 62.5 80 50 85 C37.5 80 25 65 25 50 L25 25 Z" 
                          stroke="#4A4A4A" stroke-width="2.5" fill="none"/>
                    <ellipse cx="50" cy="35" rx="10" ry="12" fill="#8B4545"/>
                    <ellipse cx="50" cy="44" rx="18" ry="4" fill="#6B3434"/>
                    <ellipse cx="47" cy="32" rx="3" ry="4" fill="#A85555" opacity="0.6"/>
                    <ellipse cx="50" cy="58" rx="14" ry="7" stroke="#4A4A4A" stroke-width="2" fill="none"/>
                    <circle cx="50" cy="58" r="4.5" fill="#4A4A4A"/>
                    <circle cx="50" cy="58" r="2" fill="#2A2A2A"/>
                    <line x1="40" y1="70" x2="60" y2="70" stroke="#8B4545" stroke-width="1.5"/>
                </svg>
            </div>
            <div class="title-container">
                <div class="title">Warne</div>
                <div class="subtitle">AI SOC AGENT</div>
            </div>
        </div>
        <div class="status-container">
            <div class="status-dot"></div>
            <div class="status-text" id="statusText">Active</div>
        </div>
    </div>
    
    <div class="main-container">
        <div class="sidebar" id="sidebar">
            <div class="card">
                <div class="card-title">OVERVIEW</div>
                <div class="metrics-grid" id="metricsGrid">
                </div>
            </div>
            
            <div class="card">
                <div class="card-title">RECENT THREATS FOR THIS HUNT</div>
                <div class="threat-list" id="threatList">
                </div>
            </div>
        </div>
        
        <div class="chat-section" id="chatSection">
            <div class="chat-window">
                <div class="expand-button" id="expandButton" onclick="toggleExpand()">
                    <svg viewBox="0 0 24 24" fill="none" stroke="#5a5a5a" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M7 13l5 5 5-5M7 6l5 5 5-5"/>
                    </svg>
                </div>
                
                <div class="chat-messages" id="chatMessages">
                    <div class="message-container" id="messageContainer">
                    </div>
                </div>
            </div>
            
            <div class="input-area">
                <input type="text" class="input-field" id="inputField" placeholder="Ask about threats, investigate events, or request analysis...">
                <div class="send-button" onclick="sendMessage()"></div>
            </div>
        </div>
    </div>
    
    <script>
        // Python-JavaScript Bridge
        function sendMessage() {
            const input = document.getElementById('inputField');
            const message = input.value.trim();
            if (!message) return;
            
            // Add user message
            addMessage(message, true);
            input.value = '';
            
            // Call Python backend
            pywebview.api.send_message(message).then(response => {
                if (response) {
                    addMessage(response.text, false, response.alert);
                }
            });
        }
        
        function addMessage(text, isUser, alert = null) {
            const container = document.getElementById('messageContainer');
            const message = document.createElement('div');
            message.className = 'message' + (isUser ? ' user' : '');
            
            const avatar = document.createElement('div');
            avatar.className = 'avatar';
            avatar.textContent = isUser ? 'M' : 'AI';
            
            const bubble = document.createElement('div');
            bubble.className = 'message-bubble';
            
            const messageText = document.createElement('div');
            messageText.className = 'message-text';
            messageText.textContent = text;
            bubble.appendChild(messageText);
            
            if (alert && !isUser) {
                const alertBadge = document.createElement('div');
                alertBadge.className = 'alert-badge';
                
                const alertTitle = document.createElement('div');
                alertTitle.className = 'alert-title';
                alertTitle.textContent = alert.title;
                
                const alertText = document.createElement('div');
                alertText.className = 'alert-text';
                alertText.textContent = alert.text;
                
                alertBadge.appendChild(alertTitle);
                alertBadge.appendChild(alertText);
                bubble.appendChild(alertBadge);
            }
            
            message.appendChild(avatar);
            message.appendChild(bubble);
            container.appendChild(message);
            
            // Scroll to bottom
            const chatMessages = document.getElementById('chatMessages');
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }
        
        function addMetric(value, label, row, col) {
            const grid = document.getElementById('metricsGrid');
            const metric = document.createElement('div');
            metric.className = 'metric-box';
            metric.style.gridRow = row + 1;
            metric.style.gridColumn = col + 1;
            
            metric.innerHTML = `
                <div class="metric-value">${value}</div>
                <div class="metric-label">${label}</div>
            `;
            
            grid.appendChild(metric);
        }
        
        function addThreat(icon, title, meta, severity) {
            const list = document.getElementById('threatList');
            const threat = document.createElement('div');
            threat.className = 'threat-item';
            
            threat.innerHTML = `
                <div class="threat-icon ${severity}">${icon}</div>
                <div class="threat-content">
                    <div class="threat-title">${title}</div>
                    <div class="threat-meta">${meta}</div>
                </div>
            `;
            
            list.appendChild(threat);
        }
        
        function updateStatus(text) {
            document.getElementById('statusText').textContent = text;
        }
        
        function clearChat() {
            document.getElementById('messageContainer').innerHTML = '';
        }
        
        function clearMetrics() {
            document.getElementById('metricsGrid').innerHTML = '';
        }
        
        function clearThreats() {
            document.getElementById('threatList').innerHTML = '';
        }
        
        function toggleExpand() {
            const chatSection = document.getElementById('chatSection');
            const sidebar = document.getElementById('sidebar');
            const expandButton = document.getElementById('expandButton');
            
            chatSection.classList.toggle('expanded');
            sidebar.classList.toggle('hidden');
            expandButton.classList.toggle('expanded');
        }
        
        // Handle Enter key
        document.getElementById('inputField').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });
    </script>
</body>
</html>
        """
    
    def start(self):
        """Start the GUI"""
        # Create API class for Python-JavaScript communication
        class API:
            def __init__(self, gui_instance):
                self.gui = gui_instance
                
            def send_message(self, message):
                """Called from JavaScript when user sends a message"""
                if self.gui.on_send_message:
                    # Call your AI agent
                    response = self.gui.on_send_message(message)
                    return response
                return {'text': 'No handler configured', 'alert': None}
        
        self.api = API(self)
        
        # Create window with HTML content
        self.window = webview.create_window(
            'Warne AI - SOC Agent',
            html=self._get_html_content(),
            js_api=self.api,
            width=1400,
            height=900,
            resizable=True,
            background_color='#e8e9eb'
        )
        
        # Start webview
        webview.start(debug=False)
        
    # Helper methods to interact with GUI from Python
    def add_message(self, text: str, is_user: bool = False, alert: dict = None):
        """Add a message to the chat"""
        if self.window:
            self.window.evaluate_js(
                f'addMessage({json.dumps(text)}, {json.dumps(is_user)}, {json.dumps(alert)})'
            )
            
    def add_metric(self, value: str, label: str, row: int, col: int):
        """Add a metric to overview"""
        if self.window:
            self.window.evaluate_js(
                f'addMetric({json.dumps(value)}, {json.dumps(label)}, {row}, {col})'
            )
            
    def add_threat(self, icon: str, title: str, meta: str, severity: str = "medium"):
        """Add a threat to the list"""
        if self.window:
            self.window.evaluate_js(
                f'addThreat({json.dumps(icon)}, {json.dumps(title)}, {json.dumps(meta)}, {json.dumps(severity)})'
            )
            
    def update_status(self, text: str):
        """Update status indicator"""
        if self.window:
            self.window.evaluate_js(f'updateStatus({json.dumps(text)})')
            
    def clear_chat(self):
        """Clear all messages"""
        if self.window:
            self.window.evaluate_js('clearChat()')
            
    def clear_metrics(self):
        """Clear all metrics"""
        if self.window:
            self.window.evaluate_js('clearMetrics()')
            
    def clear_threats(self):
        """Clear all threats"""
        if self.window:
            self.window.evaluate_js('clearThreats()')


# Example usage
if __name__ == "__main__":
    def handle_message(message: str):
        """Handle messages from user"""
        print(f"User sent: {message}")
        
        # Your AI agent logic here
        response_text = f"Received: {message}"
        
        # Return response with optional alert
        return {
            'text': response_text,
            'alert': None  # or {'title': 'ALERT', 'text': 'Alert text'}
        }
    
    gui = WarneGUI(on_send_message=handle_message)
    gui.start()
