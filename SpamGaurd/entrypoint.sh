#!/bin/sh
set -e

echo "Applying database migrations..."
python manage.py migrate --noinput

echo "Populating initial data..."
python manage.py populate

echo "Starting Gunicorn..."
exec "$@"
