#!/bin/bash
set -e

echo "=== Running xhttptunnel Unit & E2E Tests ==="
go test -v -race ./...
echo "=== All Tests Passed! ==="
