#!/bin/bash
# Mac VNC Client Setup Script
# For connecting to UltraVNC servers

echo "🍎 Mac VNC Client Setup"
echo "======================="

# Check if Homebrew is installed
if ! command -v brew &> /dev/null; then
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

echo "Installing VNC clients..."

# Install TigerVNC (command line)
brew install tiger-vnc

# Install RealVNC Viewer
brew install --cask vnc-viewer

# Install Chicken of the VNC (lightweight)
brew install --cask chicken

echo "Installation complete!"
echo ""
echo "Available VNC clients:"
echo "1. Built-in Screen Sharing: open vnc://IP:PORT"
echo "2. TigerVNC: vncviewer IP::PORT"
echo "3. RealVNC Viewer: Launch from Applications"
echo "4. Chicken: Launch from Applications"
echo ""
echo "Example connections:"
echo "open vnc://192.168.1.100:5900"
echo "vncviewer 192.168.1.100::5900"
