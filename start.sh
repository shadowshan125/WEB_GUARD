#!/bin/bash
echo "Starting WebGuard..."

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Apply migrations
echo "Applying database migrations..."
python manage.py migrate

# Start the development server
echo "Starting server at http://127.0.0.1:8000/"
python manage.py runserver
