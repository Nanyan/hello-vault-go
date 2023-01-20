#!/bin/sh

# (re)start application and its dependencies
docker compose down --volumes
echo "Starting Vault dev server with tls.."
docker compose up -d --build
echo "sleep 5s for waiting the docker compose up"
sleep 5
echo "Running sample-app-with-tls example."
go run .
echo "Stopping Vault dev server.."
# docker compose down --volumes
