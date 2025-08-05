#!/usr/bin/env python3
"""
Test script to debug deployment issues
Run this locally to check if everything works before deployment
"""

import os
import sys

def test_imports():
    """Test if all imports work"""
    print("Testing imports...")
    try:
        from app import app, db
        print("✅ App imports successfully")
        return True
    except Exception as e:
        print(f"❌ Import failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_database():
    """Test database connection"""
    print("\nTesting database...")
    try:
        from app import app, db, get_database_url
        database_url = get_database_url()
        print(f"Database URL: {database_url}")
        
        with app.app_context():
            db.create_all()
            print("✅ Database tables created successfully")
        return True
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_routes():
    """Test basic routes"""
    print("\nTesting routes...")
    try:
        from app import app
        
        with app.test_client() as client:
            # Test health endpoint
            response = client.get('/health')
            print(f"Health endpoint: {response.status_code}")
            
            # Test debug endpoint
            response = client.get('/debug')
            print(f"Debug endpoint: {response.status_code}")
            
            # Test main page
            response = client.get('/')
            print(f"Main page: {response.status_code}")
            
        print("✅ Routes test completed")
        return True
    except Exception as e:
        print(f"❌ Routes test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("🚀 Testing Private Messenger deployment...")
    print("=" * 50)
    
    tests = [
        test_imports,
        test_database,
        test_routes
    ]
    
    results = []
    for test in tests:
        results.append(test())
    
    print("\n" + "=" * 50)
    print("📊 Test Results:")
    for i, result in enumerate(results):
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"Test {i+1}: {status}")
    
    if all(results):
        print("\n🎉 All tests passed! Ready for deployment.")
    else:
        print("\n⚠️  Some tests failed. Check the errors above.")
        sys.exit(1)

if __name__ == "__main__":
    main() 