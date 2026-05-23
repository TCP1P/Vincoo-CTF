#!/bin/bash

# Build the Docker image
echo "Building Docker image..."
docker build -t uma ./challenge

# Stop and remove any existing container with the same name
echo "Stopping and removing existing container (if any)..."
docker stop uma 2>/dev/null || true
docker rm uma 2>/dev/null || true

# Run the container
echo "Starting container..."
docker run -d \
  --name uma \
  -p 8080:8080 \
  uma

echo "Container started successfully!"
echo "Application is running at http://localhost:8080"
echo ""
echo "To view logs: docker logs uma"
echo "To stop: docker stop uma"
echo "To remove: docker rm uma"
