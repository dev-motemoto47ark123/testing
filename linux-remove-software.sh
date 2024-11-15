#!/bin/bash

# Function to remove a package
remove_package() {
    local package_name=$1
    echo "Attempting to remove $package_name..."
    sudo apt-get remove -y $package_name
    if [ $? -eq 0 ]; then
        echo "✓ Package $package_name removed successfully!"
    else
        echo "✗ Error removing package $package_name"
    fi
}

# List of packages to remove
packages=(
    "rkhunter"
    "python3"
)

# Remove each package in the list
for package in "${packages[@]}"; do
    remove_package $package
done

echo "All specified packages have been processed for removal."
