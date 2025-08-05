#!/usr/bin/env python3
"""
Comprehensive test script for Private Messenger App
Tests all major functionality including admin system and encryption
"""

import requests
import json
import time
import sys
from datetime import datetime

BASE_URL = "http://127.0.0.1:5000"

def test_health():
    """Test health endpoint"""
    print("🔍 Testing health endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/health")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Health check passed: {data.get('status', 'unknown')}")
            return True
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return False

def test_main_pages():
    """Test main page endpoints"""
    print("\n🔍 Testing main pages...")
    pages = ['/', '/login', '/register', '/admin']
    
    for page in pages:
        try:
            response = requests.get(f"{BASE_URL}{page}")
            if response.status_code in [200, 302]:  # 302 is redirect to login
                print(f"✅ {page} - OK ({response.status_code})")
            else:
                print(f"❌ {page} - Failed ({response.status_code})")
        except Exception as e:
            print(f"❌ {page} - Error: {e}")

def test_api_endpoints():
    """Test API endpoints (should return proper responses)"""
    print("\n🔍 Testing API endpoints...")
    
    # Test endpoints that should return JSON responses
    api_endpoints = [
        '/api/online_users',
        '/api/conversations',
        '/api/friend_requests',
        '/api/friends'
    ]
    
    for endpoint in api_endpoints:
        try:
            response = requests.get(f"{BASE_URL}{endpoint}")
            if response.status_code == 302:  # Redirect to login (expected)
                print(f"✅ {endpoint} - Redirect to login (expected)")
            elif response.status_code == 200:
                print(f"✅ {endpoint} - OK")
            else:
                print(f"⚠️ {endpoint} - Status {response.status_code}")
        except Exception as e:
            print(f"❌ {endpoint} - Error: {e}")

def test_admin_api():
    """Test admin API endpoints"""
    print("\n🔍 Testing admin API endpoints...")
    
    admin_endpoints = [
        '/api/admin/users',
        '/api/admin/messages',
        '/api/admin/logs',
        '/api/admin/stats',
        '/api/admin/settings'
    ]
    
    for endpoint in admin_endpoints:
        try:
            response = requests.get(f"{BASE_URL}{endpoint}")
            if response.status_code == 302:  # Redirect to login (expected)
                print(f"✅ {endpoint} - Redirect to login (expected)")
            elif response.status_code == 200:
                print(f"✅ {endpoint} - OK")
            else:
                print(f"⚠️ {endpoint} - Status {response.status_code}")
        except Exception as e:
            print(f"❌ {endpoint} - Error: {e}")

def test_encryption_functions():
    """Test encryption functions directly"""
    print("\n🔍 Testing encryption functions...")
    
    try:
        # Import the app to test encryption functions
        import sys
        import os
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        
        from app import encrypt_message, decrypt_message
        
        # Test message
        test_message = "Hello, this is a test message!"
        
        # Test encryption
        encrypted = encrypt_message(test_message)
        print(f"✅ Encryption: {test_message} -> {encrypted[:50]}...")
        
        # Test decryption
        decrypted = decrypt_message(encrypted)
        print(f"✅ Decryption: {encrypted[:50]}... -> {decrypted}")
        
        if decrypted == test_message:
            print("✅ Encryption/Decryption test passed!")
        else:
            print("❌ Encryption/Decryption test failed!")
            
    except Exception as e:
        print(f"❌ Encryption test error: {e}")

def test_database_connection():
    """Test database connection"""
    print("\n🔍 Testing database connection...")
    
    try:
        import sys
        import os
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        
        from app import db, User, Message, SystemSettings
        
        # Test basic database operations
        user_count = User.query.count()
        message_count = Message.query.count()
        settings_count = SystemSettings.query.count()
        
        print(f"✅ Database connected successfully!")
        print(f"   - Users: {user_count}")
        print(f"   - Messages: {message_count}")
        print(f"   - Settings: {settings_count}")
        
    except Exception as e:
        print(f"❌ Database test error: {e}")

def test_rate_limiting_disabled():
    """Test that rate limiting is disabled"""
    print("\n🔍 Testing rate limiting (should be disabled)...")
    
    # Test multiple rapid requests to an endpoint
    endpoint = "/health"
    responses = []
    
    for i in range(10):
        try:
            response = requests.get(f"{BASE_URL}{endpoint}")
            responses.append(response.status_code)
        except Exception as e:
            print(f"❌ Request {i+1} failed: {e}")
    
    # Check if all requests succeeded (no 429 errors)
    if 429 not in responses:
        print("✅ Rate limiting is disabled - all requests succeeded")
    else:
        print("❌ Rate limiting is still active - found 429 errors")

def run_comprehensive_test():
    """Run all tests"""
    print("🚀 Starting comprehensive app test...")
    print("=" * 50)
    
    tests = [
        test_health,
        test_main_pages,
        test_api_endpoints,
        test_admin_api,
        test_encryption_functions,
        test_database_connection,
        test_rate_limiting_disabled
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} failed with exception: {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! App is working correctly.")
    else:
        print("⚠️ Some tests failed. Check the output above.")
    
    return passed == total

if __name__ == "__main__":
    success = run_comprehensive_test()
    sys.exit(0 if success else 1) 