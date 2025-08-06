#!/usr/bin/env python3
import sys
import os

# Add current directory to path
sys.path.insert(0, '/workspace')

print("=== Flask App Startup Diagnostics ===")
print(f"Python version: {sys.version}")
print(f"Current directory: {os.getcwd()}")
print(f"PYTHONPATH: {sys.path}")

try:
    print("\n1. Testing Flask import...")
    import flask
    print(f"   ✓ Flask {flask.__version__} imported successfully")
except ImportError as e:
    print(f"   ✗ Flask import failed: {e}")
    sys.exit(1)

try:
    print("\n2. Testing app import...")
    from app import app, db
    print("   ✓ App imported successfully")
except ImportError as e:
    print(f"   ✗ App import failed: {e}")
    sys.exit(1)

try:
    print("\n3. Initializing database...")
    with app.app_context():
        db.create_all()
    print("   ✓ Database initialized")
except Exception as e:
    print(f"   ✗ Database initialization failed: {e}")
    sys.exit(1)

try:
    print("\n4. Starting Flask server...")
    print("   Server will start on http://localhost:5001")
    print("   Press Ctrl+C to stop")
    print("=" * 50)
    app.run(debug=True, port=5001, host='0.0.0.0')
except KeyboardInterrupt:
    print("\n   Server stopped by user")
except Exception as e:
    print(f"   ✗ Server failed to start: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)