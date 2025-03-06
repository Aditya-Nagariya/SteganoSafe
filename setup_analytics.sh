#!/bin/bash

# Setup script for analytics dashboard
echo "Setting up analytics dashboard..."

# Make sure we're in the right directory
cd "$(dirname "$0")"

# Setup static directories
echo "Setting up static directories..."
python setup_static.py

# Generate test data for analytics
echo "Generating test data for analytics..."
python generate_test_data.py

# Print completion message
echo "Setup complete! You can now access the analytics dashboard at /admin/analytics"
echo "Remember to restart your Flask application if it's already running."
