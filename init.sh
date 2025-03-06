#!/bin/bash
# Initialize the application

echo "Setting up SteganoSafe application..."

# Run the static directory setup
echo "Setting up static directories..."
python setup_static.py

# Generate favicon
echo "Generating favicon..."
python create_favicon.py

echo "Setup complete!"
echo "You can now run the application with: python app.py"
