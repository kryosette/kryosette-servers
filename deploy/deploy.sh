#!/bin/bash

# deploy.sh - A script for applying system settings

CONFIG_FILE="99-network-security.conf"
SOURCE_PATH="./sysctl/$CONFIG_FILE"
TARGET_PATH="/etc/sysctl.d/$CONFIG_FILE"

echo "Deploying sysctl configuration locally..."

# Check the existence of the source file
if [ ! -f "$SOURCE_PATH" ]; then
    echo "ERROR: Source file $SOURCE_PATH not found!"
    exit 1
fi

# Copying with rights verification
echo "Copying $SOURCE_PATH to $TARGET_PATH"
sudo cp "$SOURCE_PATH" "$TARGET_PATH"

# Checking the success of copying
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to copy file! Trying alternative method..."
    
    # Let's try an alternative way - create a temporary file
    sudo tee "$TARGET_PATH" < "$SOURCE_PATH" > /dev/null
fi

# Setting the rights
sudo chmod 644 "$TARGET_PATH"

# Applying the settings
echo "Applying settings..."
sudo sysctl -p "$TARGET_PATH"

echo "Done! Current settings:"
sysctl net.ipv4.tcp_syncookies net.ipv4.tcp_max_syn_backlog net.core.somaxconn