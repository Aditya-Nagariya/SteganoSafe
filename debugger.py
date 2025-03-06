#!/usr/bin/env python3
import requests
import json
import os
import sys

def debug_analytics_api():
    """Debug the analytics API responses"""
    # Base URL for local development
    base_url = "http://127.0.0.1:8080"
    
    # Endpoints to test
    endpoints = [
        "/admin/api/analytics/summary",
        "/admin/api/debug/analytics"
    ]
    
    print("\n=== Analytics API Debugger ===\n")
    
    # Create a session to maintain cookies
    session = requests.Session()
    
    # First, try to login as admin
    login_data = {
        "username": "admin",
        "password": "admin123"
    }
    
    try:
        print("Logging in as admin...")
        response = session.post(f"{base_url}/login", data=login_data)
        if response.status_code != 200:
            print(f"Login failed: Status code {response.status_code}")
            return
        
        # Test each endpoint
        for endpoint in endpoints:
            print(f"\nTesting endpoint: {endpoint}")
            response = session.get(f"{base_url}{endpoint}")
            
            print(f"Status Code: {response.status_code}")
            if response.status_code == 200:
                try:
                    data = response.json()
                    print("Response Data:")
                    print(json.dumps(data, indent=2))
                except json.JSONDecodeError:
                    print("Response is not valid JSON")
                    print(response.text[:200] + "..." if len(response.text) > 200 else response.text)
            else:
                print("Error Response:")
                print(response.text[:200] + "..." if len(response.text) > 200 else response.text)
    
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    debug_analytics_api()
