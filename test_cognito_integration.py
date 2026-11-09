#!/usr/bin/env python3
"""
Test script for AWS Cognito integration with DocShield Backend
This script helps verify that your API endpoints work correctly with JWT tokens
"""

import requests
import json
import sys
from typing import Dict, Optional

class DocShieldAPITester:
    def __init__(self, api_base_url: str, jwt_token: Optional[str] = None):
        self.api_base_url = api_base_url.rstrip('/')
        self.jwt_token = jwt_token
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        if jwt_token:
            self.headers['Authorization'] = f'Bearer {jwt_token}'
    
    def set_token(self, token: str):
        """Update the JWT token for authenticated requests"""
        self.jwt_token = token
        self.headers['Authorization'] = f'Bearer {token}'
    
    def test_signup(self, user_data: Dict) -> Dict:
        """Test simplified user signup endpoint"""
        print(f"🧪 Testing simplified signup endpoint...")
        
        url = f"{self.api_base_url}/signup"
        response = requests.post(url, json=user_data, headers=self.headers)
        
        print(f"Status: {response.status_code}")
        try:
            result = response.json()
            print(f"Response: {json.dumps(result, indent=2)}")
            return result
        except:
            print(f"Raw response: {response.text}")
            return {}
    
    def test_complete_profile(self, profile_data: Dict) -> Dict:
        """Test profile completion endpoint"""
        print(f"🧪 Testing complete_profile endpoint...")
        
        if not self.jwt_token:
            print("❌ No JWT token provided")
            return {}
        
        url = f"{self.api_base_url}/complete_profile"
        response = requests.post(url, json=profile_data, headers=self.headers)
        
        print(f"Status: {response.status_code}")
        try:
            result = response.json()
            print(f"Response: {json.dumps(result, indent=2)}")
            return result
        except:
            print(f"Raw response: {response.text}")
            return {}
    
    def test_login(self) -> Dict:
        """Test login endpoint with JWT token"""
        print(f"🧪 Testing login endpoint with JWT...")
        
        if not self.jwt_token:
            print("❌ No JWT token provided")
            return {}
        
        url = f"{self.api_base_url}/login"
        response = requests.post(url, json={}, headers=self.headers)
        
        print(f"Status: {response.status_code}")
        try:
            result = response.json()
            print(f"Response: {json.dumps(result, indent=2)}")
            return result
        except:
            print(f"Raw response: {response.text}")
            return {}
    
    def test_sync_user(self) -> Dict:
        """Test Cognito user sync endpoint"""
        print(f"🧪 Testing sync_cognito_user endpoint...")
        
        if not self.jwt_token:
            print("❌ No JWT token provided")
            return {}
        
        url = f"{self.api_base_url}/sync_cognito_user"
        response = requests.post(url, json={}, headers=self.headers)
        
        print(f"Status: {response.status_code}")
        try:
            result = response.json()
            print(f"Response: {json.dumps(result, indent=2)}")
            return result
        except:
            print(f"Raw response: {response.text}")
            return {}
    
    def test_get_user_details(self, email: Optional[str] = None) -> Dict:
        """Test get user details endpoint"""
        print(f"🧪 Testing get_userdetails endpoint...")
        
        url = f"{self.api_base_url}/get_userdetails"
        
        # If no token, use email query parameter
        if not self.jwt_token and email:
            url += f"?userEmail={email}"
        
        response = requests.get(url, headers=self.headers)
        
        print(f"Status: {response.status_code}")
        try:
            result = response.json()
            print(f"Response: {json.dumps(result, indent=2)}")
            return result
        except:
            print(f"Raw response: {response.text}")
            return {}
    
    def test_update_profile(self, profile_data: Dict) -> Dict:
        """Test update profile endpoint"""
        print(f"🧪 Testing update_profile endpoint...")
        
        url = f"{self.api_base_url}/update_profile"
        response = requests.put(url, json=profile_data, headers=self.headers)
        
        print(f"Status: {response.status_code}")
        try:
            result = response.json()
            print(f"Response: {json.dumps(result, indent=2)}")
            return result
        except:
            print(f"Raw response: {response.text}")
            return {}

def main():
    print("🚀 DocShield Cognito Integration Tester")
    print("=" * 50)
    
    # Configuration
    API_BASE_URL = input("Enter your API Gateway URL (e.g., https://abc123.execute-api.us-east-1.amazonaws.com/prod): ").strip()
    
    if not API_BASE_URL:
        print("❌ API URL is required")
        return
    
    tester = DocShieldAPITester(API_BASE_URL)
    
    print("\n📋 Test Options:")
    print("1. Test signup (no token needed)")
    print("2. Test with JWT token (login, sync, get details, update profile)")
    print("3. Test get user details with email (no token)")
    
    choice = input("\nEnter your choice (1-3): ").strip()
    
    if choice == "1":
        # Test simplified signup
        print("\n🔄 Testing Simplified Signup...")
        user_data = {
            "email": input("Email: ")
        }
        result = tester.test_signup(user_data)
        
        if result.get("userid"):
            print(f"✅ User created with ID: {result['userid']}")
            print(f"📝 Profile setup: {result.get('profileSetup', {})}")
    
    elif choice == "2":
        # Test with JWT token
        jwt_token = input("Enter your JWT token: ").strip()
        
        if not jwt_token:
            print("❌ JWT token is required")
            return
        
        tester.set_token(jwt_token)
        
        print("\n🔄 Testing JWT Authentication Flow...")
        
        # Test login
        print("\n" + "-" * 30)
        login_result = tester.test_login()
        
        # Test sync
        print("\n" + "-" * 30)
        sync_result = tester.test_sync_user()
        
        # Test get user details
        print("\n" + "-" * 30)
        details_result = tester.test_get_user_details()
        
        # Test profile completion
        print("\n" + "-" * 30)
        complete_data = {
            "firstName": "John",
            "lastName": "Doe", 
            "userType": "Student",
            "institution": "Test University",
            "phone": "+1234567890"
        }
        complete_result = tester.test_complete_profile(complete_data)
        
        # Test update profile
        print("\n" + "-" * 30)
        update_data = {
            "designation": "Research Assistant",
            "educationLevel": "Graduate"
        }
        update_result = tester.test_update_profile(update_data)
    
    elif choice == "3":
        # Test get user details with email
        email = input("Enter user email: ").strip()
        if email:
            print("\n🔄 Testing Get User Details with Email...")
            tester.test_get_user_details(email)
        else:
            print("❌ Email is required")
    
    else:
        print("❌ Invalid choice")
    
    print("\n✅ Testing completed!")

if __name__ == "__main__":
    main()