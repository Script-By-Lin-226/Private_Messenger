import os
import sys

# Add the parent directory to the path so we can import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from app import app, db
    
    # Initialize database tables safely for serverless functions
    def init_db():
        try:
            with app.app_context():
                db.create_all()
        except Exception as e:
            print(f"Database initialization warning: {e}")
            # Continue without database initialization for now
    
    # Don't initialize at import time, let it happen on first request
    
except Exception as e:
    print(f"Error importing app: {e}")
    import traceback
    traceback.print_exc()
    raise

# Add error handler for unhandled exceptions
@app.errorhandler(Exception)
def handle_exception(e):
    print(f"Unhandled exception: {e}")
    import traceback
    traceback.print_exc()
    return jsonify({'error': 'Internal server error'}), 500

# This is the entry point for serverless functions 