"""
Utility script to inspect all routes registered in the Flask application.
This helps diagnose route conflicts.
"""
import sys
import os

# Add parent directory to path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)

from steganography_app import create_app

app = create_app()

def print_routes():
    """Print all registered routes in the application"""
    print("\nRegistered Routes:")
    print("-" * 80)
    format_str = "{:40s} {:40s} {:15s}"
    print(format_str.format("Endpoint", "Route", "Methods"))
    print("-" * 80)
    
    # Sort routes by endpoint for easier reading
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append((rule.endpoint, rule.rule, ', '.join(rule.methods)))
    
    for endpoint, route, methods in sorted(routes):
        print(format_str.format(endpoint, route, methods))

if __name__ == "__main__":
    print_routes()
