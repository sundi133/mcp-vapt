#!/usr/bin/env python3
"""
Startup script for fly.io deployment
Runs both Flask app and MCP server together
"""

import os
import sys
import threading
import time
from multiprocessing import Process

def start_flask_app():
    """Start the Flask application"""
    print("🚀 Starting Flask app...")
    os.environ['FLASK_APP_URL'] = 'http://127.0.0.1:6991'
    os.system("python3 ExternalAttacker-App.py")

def start_mcp_server():
    """Start the MCP server"""
    print("🔧 Starting MCP server...")
    # Wait a bit for Flask to start
    time.sleep(5)
    os.environ['PORT'] = '8000'  # Set PORT to trigger SSE mode
    os.system("python3 ExternalAttacker-MCP.py")

def main():
    """Main startup function"""
    print("🌟 ExternalAttacker-MCP Cloud Startup")
    print("=====================================")
    
    # Start Flask app in a separate process
    flask_process = Process(target=start_flask_app)
    flask_process.start()
    
    # Start MCP server in a separate process  
    mcp_process = Process(target=start_mcp_server)
    mcp_process.start()
    
    try:
        # Wait for both processes
        flask_process.join()
        mcp_process.join()
    except KeyboardInterrupt:
        print("🛑 Shutting down services...")
        flask_process.terminate()
        mcp_process.terminate()
        flask_process.join()
        mcp_process.join()

if __name__ == "__main__":
    main() 