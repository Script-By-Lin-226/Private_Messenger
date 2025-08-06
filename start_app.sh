#!/bin/bash
cd /workspace
source venv/bin/activate
export FLASK_ENV=development
export FLASK_DEBUG=1
echo "Starting Flask application..."
echo "Make sure to access it at: http://localhost:5001"
python3 app.py