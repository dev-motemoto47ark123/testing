#!/bin/bash

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Backup current sources list
mv /etc/apt/sources.list /etc/apt/sources.list.backup
echo "Current sources.list backed up to sources.list.backup"

# Create new sources list
touch /etc/apt/sources.list

# Get Ubuntu version codename
UBUNTU_VERSION=$(lsb_release -sc)

# Add default Ubuntu repositories
echo "deb http://archive.ubuntu.com/ubuntu/ $UBUNTU_VERSION main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ $UBUNTU_VERSION-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ $UBUNTU_VERSION-security main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ $UBUNTU_VERSION-backports main restricted universe multiverse" > /etc/apt/sources.list

# Remove all repository files from sources.list.d
rm -rf /etc/apt/sources.list.d/*
echo "Removed additional repository files"

# Clean and update
apt clean
echo "Cleaned package lists"
apt update
echo "Updated package lists"

echo "Repository restoration complete!"
