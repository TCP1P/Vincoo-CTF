#!/bin/bash

echo "Stopping uma application..."

# Stop the container
echo "Stopping container..."
docker stop uma 2>/dev/null || echo "Container not running"

# Remove the container
echo "Removing container..."
docker rm uma 2>/dev/null || echo "Container not found"

echo "uma application stopped and cleaned up!"
