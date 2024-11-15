#!/bin/bash

# Function to list all users
list_all_users() {
    echo -e "\nListing all users:"
    echo "===================="
    cut -d: -f1,3,4,6,7 /etc/passwd
}

# Function to list normal users
list_normal_users() {
    echo -e "\nListing normal users (UID >= 1000):"
    echo "======================================"
    awk -F: '$3 >= 1000 && $3 != 65534 {print $1 " (UID: " $3 ")"}' /etc/passwd
}

# Function to list system users
list_system_users() {
    echo -e "\nListing system users (UID < 1000):"
    echo "==================================="
    awk -F: '$3 < 1000 {print $1 " (UID: " $3 ")"}' /etc/passwd
}

# Function to list admin users (sudoers)
list_admin_users() {
    echo -e "\nListing admin users (sudoers):"
    echo "==============================="
    grep -Po '^sudo.+:\K.*$' /etc/group | tr ',' '\n'
}

# Function to add a new user
add_user() {
    read -p "Enter username for new account: " username
    if [ -z "$username" ]; then
        echo "Username cannot be empty"
        return
    fi
    
    sudo useradd -m "$username"
    sudo passwd "$username"
    
    read -p "Make this user an administrator? (y/n): " make_admin
    if [ "$make_admin" = "y" ]; then
        sudo usermod -aG sudo "$username"
        echo "User $username added as administrator"
    else
        echo "User $username added as normal user"
    fi
}

# Function to remove a user
remove_user() {
    read -p "Enter username to remove: " username
    if [ -z "$username" ]; then
        echo "Username cannot be empty"
        return
    fi
    
    read -p "Remove home directory? (y/n): " remove_home
    if [ "$remove_home" = "y" ]; then
        sudo userdel -r "$username"
    else
        sudo userdel "$username"
    fi
    echo "User $username has been removed"
}

# Function to modify user admin status
modify_admin_status() {
    read -p "Enter username to modify: " username
    if [ -z "$username" ]; then
        echo "Username cannot be empty"
        return
    fi
    
    if groups "$username" | grep -q "\bsudo\b"; then
        read -p "User is currently an admin. Remove admin rights? (y/n): " remove_admin
        if [ "$remove_admin" = "y" ]; then
            sudo deluser "$username" sudo
            echo "Removed admin rights from $username"
        fi
    else
        read -p "User is not an admin. Add admin rights? (y/n): " add_admin
        if [ "$add_admin" = "y" ]; then
            sudo usermod -aG sudo "$username"
            echo "Added admin rights to $username"
        fi
    fi
}

# Main menu
while true; do
    echo -e "\n=== Linux User Management Tool ==="
    echo "1. List all users"
    echo "2. List normal users"
    echo "3. List system users"
    echo "4. List admin users"
    echo "5. Add new user"
    echo "6. Remove user"
    echo "7. Modify user admin status"
    echo "8. Exit"
    
    read -p "Enter your choice (1-8): " choice
    
    case $choice in
        1) list_all_users ;;
        2) list_normal_users ;;
        3) list_system_users ;;
        4) list_admin_users ;;
        5) add_user ;;
        6) remove_user ;;
        7) modify_admin_status ;;
        8) 
            echo "Thanks for using my script! Hope it helped!"
            echo "If you found this useful, follow me on GitHub:"
            echo "github.com/motoemoto47ark123"
            exit 0 ;;
        *) echo "Invalid option. Please try again." ;;
    esac
done