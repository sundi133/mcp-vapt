#!/bin/bash

echo "🚀 Starting ExternalAttacker-MCP Services..."

# Start Flask app in background
echo "Starting Flask app on port 6991..."
source .venv/bin/activate
python3 ExternalAttacker-App.py &
FLASK_PID=$!

# Wait for Flask to start
sleep 3

# Start MCP server
echo "Starting MCP server..."
echo "Flask PID: $FLASK_PID"
echo "Use 'kill $FLASK_PID' to stop the Flask app"

python3 ExternalAttacker-MCP.py

# Cleanup
kill $FLASK_PID 2>/dev/null
