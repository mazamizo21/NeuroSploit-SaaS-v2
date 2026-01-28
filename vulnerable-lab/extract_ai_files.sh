#!/bin/bash
# Extract files created by AI from the last container

echo "Finding last tazosploit container..."
CONTAINER_ID=$(docker ps -a --filter "ancestor=tazosploit-kali:minimal" --format "{{.ID}}" | head -1)

if [ -z "$CONTAINER_ID" ]; then
    echo "❌ No tazosploit container found"
    exit 1
fi

echo "Found container: $CONTAINER_ID"
echo ""

# Create extraction directory
mkdir -p extracted_files
cd extracted_files

echo "📦 Extracting AI-created files..."
echo ""

# Extract zip archives
echo "1. Extracting zip archives..."
docker cp "$CONTAINER_ID:/root/2026-01-12_06-46-52.zip" . 2>/dev/null && echo "  ✓ 2026-01-12_06-46-52.zip" || echo "  ✗ Not found"
docker cp "$CONTAINER_ID:/root/2026-01-12_08-51-31.zip" . 2>/dev/null && echo "  ✓ 2026-01-12_08-51-31.zip" || echo "  ✗ Not found"

# Extract password/credential files
echo ""
echo "2. Extracting credential files..."
docker cp "$CONTAINER_ID:/root/mysql_databases.txt" . 2>/dev/null && echo "  ✓ mysql_databases.txt" || echo "  ✗ Not found"
docker cp "$CONTAINER_ID:/root/flags.txt" . 2>/dev/null && echo "  ✓ flags.txt" || echo "  ✗ Not found"

# Extract nmap scans
echo ""
echo "3. Extracting nmap scans..."
docker cp "$CONTAINER_ID:/root/nmap" . 2>/dev/null && echo "  ✓ nmap/ directory" || echo "  ✗ Not found"

# List all files in /root
echo ""
echo "4. Listing all files in container /root..."
docker exec "$CONTAINER_ID" ls -lah /root/ 2>/dev/null || docker run --rm -v tazosploit_data:/root alpine ls -lah /root/

echo ""
echo "================================================"
echo "Files extracted to: $(pwd)"
echo "================================================"
ls -lh

# Unzip archives to see contents
echo ""
echo "📂 Unzipping archives..."
for zip in *.zip; do
    if [ -f "$zip" ]; then
        echo "Extracting $zip..."
        unzip -q "$zip" -d "${zip%.zip}_contents" 2>/dev/null && echo "  ✓ Extracted to ${zip%.zip}_contents/" || echo "  ✗ Failed"
    fi
done

echo ""
echo "✅ Extraction complete!"
echo ""
echo "To view passwords/credentials:"
echo "  cat mysql_databases.txt"
echo "  cat flags.txt"
echo ""
echo "To view nmap results:"
echo "  cat nmap/*.nmap"
echo ""
echo "To browse extracted archives:"
echo "  ls -R *_contents/"
