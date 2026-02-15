#!/bin/bash
# Extract all files created by AI from the container after test completion

echo "🔍 Finding tazosploit containers..."
CONTAINERS=$(docker ps -a --filter "name=tazosploit-pentest" --format "{{.Names}}" | sort -r)

if [ -z "$CONTAINERS" ]; then
    echo "❌ No tazosploit-pentest containers found"
    echo ""
    echo "Available containers:"
    docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.CreatedAt}}"
    exit 1
fi

echo "Found containers:"
echo "$CONTAINERS"
echo ""

# Use the most recent container
CONTAINER=$(echo "$CONTAINERS" | head -1)
echo "📦 Using container: $CONTAINER"
echo ""

# Create extraction directory
mkdir -p extracted
cd extracted

echo "Extracting files from /root/..."
echo ""

# Extract all zip archives
echo "1. ZIP Archives:"
docker cp "$CONTAINER:/root/" ./root_backup 2>/dev/null
if [ -d "./root_backup" ]; then
    find ./root_backup -name "*.zip" -exec cp {} . \; 2>/dev/null
    ls -lh *.zip 2>/dev/null && echo "  ✓ Copied zip files" || echo "  ✗ No zip files found"
else
    echo "  ✗ Could not access /root/"
fi

# Extract credential files
echo ""
echo "2. Credential Files:"
docker cp "$CONTAINER:/root/mysql_databases.txt" . 2>/dev/null && echo "  ✓ mysql_databases.txt" || echo "  ✗ Not found"
docker cp "$CONTAINER:/root/flags.txt" . 2>/dev/null && echo "  ✓ flags.txt" || echo "  ✗ Not found"

# Extract nmap results
echo ""
echo "3. Nmap Scans:"
docker cp "$CONTAINER:/root/nmap" . 2>/dev/null && echo "  ✓ nmap/ directory" || echo "  ✗ Not found"

# List everything in container /root
echo ""
echo "4. Complete /root/ listing:"
docker exec "$CONTAINER" ls -lah /root/ 2>/dev/null || echo "  ✗ Container not running"

echo ""
echo "================================================"
echo "Files extracted to: $(pwd)"
echo "================================================"
ls -lh

# Unzip archives
echo ""
echo "📂 Extracting zip archives..."
for zip in *.zip; do
    if [ -f "$zip" ]; then
        echo "Unzipping $zip..."
        unzip -q "$zip" -d "${zip%.zip}_contents" 2>/dev/null && echo "  ✓ Extracted" || echo "  ✗ Failed"
    fi
done

echo ""
echo "✅ Extraction complete!"
echo ""
echo "View credentials:"
echo "  cat mysql_databases.txt"
echo "  cat flags.txt"
echo ""
echo "View nmap results:"
echo "  cat nmap/*.nmap"
echo ""
echo "Browse archives:"
echo "  ls -R *_contents/"
