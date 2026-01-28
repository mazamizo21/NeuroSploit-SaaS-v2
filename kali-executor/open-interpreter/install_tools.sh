#!/bin/bash
# Install TazoSploit tools to container path

TOOL_DIR="/pentest/tools"
DEST_DIR="/usr/local/bin"

echo "Installing tools from $TOOL_DIR to $DEST_DIR..."

# Ensure destination exists
mkdir -p $DEST_DIR

# Install python dependencies (allow breaking system packages in container)
pip install requests argparse --break-system-packages --quiet

# Install tools
for tool in websearch docslookup download; do
    if [ -f "$TOOL_DIR/$tool.py" ]; then
        echo "Installing $tool..."
        cp "$TOOL_DIR/$tool.py" "$DEST_DIR/$tool"
        chmod +x "$DEST_DIR/$tool"
        
        # Verify
        if which $tool > /dev/null; then
            echo "✅ $tool installed successfully"
        else
            echo "❌ Failed to install $tool"
        fi
    else
        echo "⚠️ $tool.py not found in $TOOL_DIR"
    fi
done

echo "Tools installation complete."
