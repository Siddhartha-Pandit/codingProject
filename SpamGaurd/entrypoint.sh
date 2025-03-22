#!/bin/sh
set -e

echo "Applying database migrations..."
python manage.py migrate --noinput

echo "Populating initial data..."
python manage.py populate_data

echo "Starting Gunicorn..."
exec "$@"
