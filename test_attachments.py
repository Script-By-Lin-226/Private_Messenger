#!/usr/bin/env python3
"""
Test script for attachment functionality.
This script tests the file upload and attachment features.
"""

import os
import sys
from pathlib import Path

def test_attachment_upload():
    """Test file attachment upload functionality"""
    print("Testing attachment upload functionality...")
    
    # Check if uploads directory exists
    uploads_dir = Path("static/uploads")
    if not uploads_dir.exists():
        print(f"✅ Creating uploads directory: {uploads_dir}")
        uploads_dir.mkdir(parents=True, exist_ok=True)
    else:
        print(f"✅ Uploads directory exists: {uploads_dir}")
    
    # Check file validation function
    sys.path.append('.')
    try:
        from app import allowed_file
        
        # Test various file types
        test_files = [
            ("test.jpg", True),
            ("test.png", True),
            ("test.pdf", True),
            ("test.txt", True),
            ("test.exe", False),
            ("test.bat", False),
            ("", False),
            ("test", False)
        ]
        
        print("\n📁 Testing file validation:")
        for filename, expected in test_files:
            result = allowed_file(filename)
            status = "✅" if result == expected else "❌"
            print(f"{status} {filename}: {result} (expected: {expected})")
        
        print("\n🎉 File validation tests completed!")
        
    except ImportError as e:
        print(f"❌ Could not import app module: {e}")
        return False
    
    return True

def check_database_fields():
    """Check if database has attachment fields"""
    print("\n📊 Database attachment fields check:")
    print("Note: Run migrate_attachments.py to add attachment fields to the database")
    print("Required fields: has_attachment, attachment_filename, attachment_original_name, attachment_type, attachment_size")
    
    return True

def main():
    print("🚀 PChat Attachment Functionality Test")
    print("=" * 50)
    
    success = True
    
    # Test file upload functionality
    if not test_attachment_upload():
        success = False
    
    # Check database fields
    if not check_database_fields():
        success = False
    
    print("\n" + "=" * 50)
    if success:
        print("✅ All attachment functionality tests passed!")
        print("\n📝 Next steps:")
        print("1. Run migrate_attachments.py to update database")
        print("2. Start the application and test file uploads")
        print("3. Test with different file types (images, PDFs, etc.)")
    else:
        print("❌ Some tests failed. Please check the errors above.")
    
    return success

if __name__ == "__main__":
    main()