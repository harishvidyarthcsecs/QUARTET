#!/bin/bash
# Ultimate Simple Firewall Rollback - Just Remove UFW

echo "========================================"
echo "Firewall Rollback - UFW Removal"
echo "========================================"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Run as root: sudo $0"
    exit 1
fi

echo "Step 1: Disabling UFW..."
ufw --force disable 2>/dev/null
echo "✓ UFW disabled"

echo ""
echo "Step 2: Removing UFW package..."
apt-get remove --purge -y ufw
apt-get autoremove -y

echo ""
echo "Step 3: Cleaning up..."
rm -rf /etc/ufw 2>/dev/null
rm -f /etc/default/ufw 2>/dev/null

echo ""
echo "========================================"
echo "✓ UFW COMPLETELY REMOVED!"
echo "========================================"
echo "System firewall is now disabled."
echo ""
