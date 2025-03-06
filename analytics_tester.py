#!/usr/bin/env python3
"""
Utility to test the analytics API endpoints directly.
This is useful for debugging issues with analytics data.
"""
import os
import sys
import json
import requests
import argparse
from datetime import datetime

# Configure the script
base_url = "http://127.0.0.1:8080"  # Change if your app runs on a different port
debug_endpoint = "/admin/api/debug/analytics"
summary_endpoint = "/admin/api/analytics/summary"
test_endpoint = "/admin/api/test-analytics"

def login_session(username="admin", password="admin123"):
    """Log in and return a session with valid cookies"""
    session = requests.Session()
    login_url = f"{base_url}/login"
    
    # Get CSRF token
    response = session.get(login_url)
    if response.status_code != 200:
        print(f"Failed to access login page: {response.status_code}")
        return None
    
    # Find CSRF token
    csrf_token = None
    for line in response.text.split('\n'):
        if 'csrf_token' in line and 'value=' in line:
            # Extract token from input element
            parts = line.split('value="')
            if len(parts) > 1:
                csrf_token = parts[1].split('"')[0]
                break
    
    if not csrf_token:
        print("Could not find CSRF token in login page")
        return None
    
    # Log in
    login_data = {
        "username": username,
        "password": password,
        "csrf_token": csrf_token
    }
    
    response = session.post(login_url, data=login_data)
    if response.url.endswith('/dashboard'):
        print(f"Login successful as {username}")
        return session
    else:
        print(f"Login failed: {response.url}")
        return None

def format_json(data):
    """Format JSON data for pretty printing"""
    return json.dumps(data, indent=2, sort_keys=True)

def test_endpoint(session, endpoint, params=None):
    """Test an endpoint and return the response"""
    try:
        url = f"{base_url}{endpoint}"
        print(f"Testing endpoint: {url}")
        
        response = session.get(url, params=params)
        print(f"Status code: {response.status_code}")
        
        if response.status_code == 200:
            try:
                data = response.json()
                if data.get('success', False):
                    print("SUCCESS: API returned success=True")
                else:
                    print("WARNING: API returned success=False")
                    if 'error' in data:
                        print(f"Error: {data['error']}")
                        
                return data
            except json.JSONDecodeError:
                print("ERROR: Response is not valid JSON")
                print(response.text[:200])
                return None
        else:
            print(f"ERROR: HTTP {response.status_code}")
            print(response.text[:200])
            return None
            
    except Exception as e:
        print(f"ERROR: {str(e)}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Test analytics API endpoints")
    parser.add_argument("--days", "-d", type=int, default=7,
                        help="Number of days for analytics period (default: 7)")
    parser.add_argument("--username", "-u", default="admin",
                        help="Username for login (default: admin)")
    parser.add_argument("--password", "-p", default="admin123",
                        help="Password for login (default: admin123)")
    parser.add_argument("--endpoint", "-e", default="all",
                        choices=["all", "debug", "summary", "test"],
                        help="Which endpoint to test (default: all)")
    
    args = parser.parse_args()
    
    # Login
    session = login_session(args.username, args.password)
    if not session:
        print("ERROR: Failed to create authenticated session")
        return 1
    
    results = {}
    
    # Test endpoints
    if args.endpoint in ["all", "debug"]:
        print("\n== Testing debug endpoint ==")
        results["debug"] = test_endpoint(session, debug_endpoint)
        
    if args.endpoint in ["all", "summary"]:
        print("\n== Testing summary endpoint ==")
        results["summary"] = test_endpoint(session, summary_endpoint, {"days": args.days})
        
    if args.endpoint in ["all", "test"]:
        print("\n== Testing test endpoint ==")
        results["test"] = test_endpoint(session, test_endpoint)
    
    # Save results to file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"analytics_test_{timestamp}.json"
    
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to {filename}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
