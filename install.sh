#!/bin/bash
# ============================================
#  Waymark Global Installer
#  Run this ONCE to make 'waymark' available
#  from anywhere on your Kali system.
# ============================================

WAYMARK_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[*] Installing Waymark globally..."

# Make the main script executable
chmod +x "$WAYMARK_DIR/waymark.sh"

# Create global symlink in /usr/local/bin
sudo ln -sf "$WAYMARK_DIR/waymark.sh" /usr/local/bin/waymark

echo "[✓] Done! You can now run 'waymark' from anywhere."
echo ""
echo "    waymark start          # Launch everything"
echo "    waymark stop           # Shut it down"
echo "    waymark status         # Check status"
echo "    waymark install-tools  # Install recon tools"
echo "    waymark db-reset       # Reset database"
echo "    waymark help           # Show help"
echo ""
