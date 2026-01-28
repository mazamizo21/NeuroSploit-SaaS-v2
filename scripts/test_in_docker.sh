#!/bin/bash
# Run tests inside the Kali Docker container

set -e

echo "============================================================"
echo "Running TazoSploit Tests Inside Docker Container"
echo "============================================================"

# Check if container is running
if ! docker ps | grep -q tazosploit-kali; then
    echo "❌ Error: tazosploit-kali container is not running"
    echo "Start it with: docker-compose up -d"
    exit 1
fi

echo "✅ Container is running"
echo ""

# Copy test file to container
echo "📦 Copying test files to container..."
docker cp tests/test_new_features.py tazosploit-kali:/pentest/test_new_features.py

# Run tests inside container
echo ""
echo "🧪 Running E2E tests inside container..."
echo "============================================================"
docker exec tazosploit-kali python3 /pentest/test_new_features.py

# Get exit code
EXIT_CODE=$?

echo ""
echo "============================================================"
if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ All tests passed!"
else
    echo "⚠️  Some tests failed (exit code: $EXIT_CODE)"
fi
echo "============================================================"

exit $EXIT_CODE
