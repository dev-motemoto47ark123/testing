#!/usr/bin/env python3
import os
import sys
import subprocess
import time

# Function to check if the script is run as root
def check_root():
    """Check if script is run as root"""
    if os.geteuid() != 0:
        print("This script must be run as root (sudo)!")
        sys.exit(1)

# Function to run a system command and return the result
def run_command(command):
    """Run system command and return result"""
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        return process.returncode, output.decode(), error.decode()
    except Exception as e:
        return 1, "", str(e)

# Function to install RKHunter if it is not already installed
def install_rkhunter():
    """Install RKHunter if not already installed"""
    print("\nChecking RKHunter installation...")
    returncode, _, _ = run_command("which rkhunter")
    if returncode != 0:
        print("Installing RKHunter...")
        returncode, output, error = run_command("apt-get install -y rkhunter")
        if returncode == 0:
            print("✓ RKHunter installed successfully!")
        else:
            print("✗ Error installing RKHunter:")
            print(error)
            return False
    else:
        print("✓ RKHunter is already installed")
    return True

# Function to run RKHunter system check
def run_rkhunter_check():
    """Run RKHunter system check"""
    print("\nRunning RKHunter system check...")
    print("This may take several minutes. Please wait.\n")
    
    # Run rkhunter check and stream output to console
    process = subprocess.Popen(["rkhunter", "--check", "--skip-keypress"], 
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT,
                             universal_newlines=True)
    
    # Read the output line by line and print it to the console
    while True:
        output = process.stdout.readline()
        if output == '' and process.poll() is not None:
            break
        if output:
            print(output.strip())
    
    success = process.poll() == 0
    
    print("\nRKHunter check complete. Results have been written to: /var/log/rkhunter.log")
    if not success:
        print("! One or more warnings were found during the system check.")
    
    # Ask the user if they want to view the log file
    response = input("\nWould you like to view the log file now? (y/n): ")
    if response.lower() == 'y':
        returncode, output, _ = run_command("cat /var/log/rkhunter.log")
        if returncode == 0:
            print("\n=== RKHunter Log File Contents ===\n")
            print(output)
        else:
            print("Error reading log file.")
    
    return success

# Function to view the RKHunter log file
def view_rkhunter_log():
    """View RKHunter log file"""
    if os.path.exists('/var/log/rkhunter.log'):
        returncode, output, _ = run_command("cat /var/log/rkhunter.log")
        if returncode == 0:
            print("\n=== RKHunter Log File Contents ===\n")
            print(output)
        else:
            print("Error reading log file.")
    else:
        print("\nNo RKHunter log file found. Please run a system check first.")

# Function to disable login for system accounts
def disable_system_accounts():
    """Disable login for system accounts"""
    print("\n=== Disabling System Accounts ===")
    system_accounts = ['bin', 'sys', 'sync', 'games', 'man', 'lp', 'mail', 
                      'news', 'uucp', 'proxy', 'www-data', 'backup', 'list',
                      'irc', 'gnats', 'nobody', 'systemd-network', 'systemd-resolve',
                      'messagebus', 'syslog', 'mysql', '_apt', 'uuidd']
    
    # Loop through each system account and disable it
    for account in system_accounts:
        print(f"\nAttempting to disable {account}...")
        returncode, output, error = run_command(f"passwd -l {account}")
        if returncode == 0:
            print(f"✓ Successfully disabled {account}")
        else:
            print(f"✗ Error disabling {account}:")
            print(error)

# Function to disable root login by changing shell to /sbin/nologin
def disable_root_login():
    """Disable root login by changing shell to /sbin/nologin"""
    print("\n=== Disabling Root Login ===")
    try:
        with open('/etc/passwd', 'r') as file:
            lines = file.readlines()
        
        with open('/etc/passwd', 'w') as file:
            for line in lines:
                if line.startswith('root:'):
                    parts = line.strip().split(':')
                    parts[-1] = '/sbin/nologin'
                    line = ':'.join(parts) + '\n'
                file.write(line)
        
        print("✓ Root login disabled successfully!")
    except Exception as e:
        print(f"✗ Error disabling root login: {str(e)}")

# Function to configure root user timeout
def configure_root_timeout():
    """Configure root user timeout"""
    print("\n=== Configuring Root User Timeout ===")
    try:
        with open('/etc/profile', 'a') as file:
            file.write("\n[ $UID -eq 0 ] && TMOUT=600\n")
        print("✓ Root user timeout configured successfully!")
    except Exception as e:
        print(f"✗ Error configuring root user timeout: {str(e)}")

# Function to disable Guest account in LightDM
def disable_guest_account():
    """Disable Guest account in LightDM"""
    print("\n=== Disabling Guest Account ===")
    try:
        lightdm_conf_path = '/etc/lightdm/lightdm.conf'
        if os.path.exists(lightdm_conf_path):
            with open(lightdm_conf_path, 'a') as file:
                file.write("\n[Seat:*]\nallow-guest=false\n")
            print("✓ Guest account disabled successfully!")
        else:
            print(f"✗ LightDM configuration file not found at {lightdm_conf_path}")
    except Exception as e:
        print(f"✗ Error disabling guest account: {str(e)}")

# Function to configure SSH settings
def configure_ssh():
    """Configure SSH settings"""
    print("\n=== Configuring SSH Settings ===")
    sshd_config_path = '/etc/ssh/sshd_config'
    ssh_config_path = '/etc/ssh/ssh_config'
    username = input("Enter the username to allow SSH access: ")

    # SSH server configuration settings
    sshd_config_settings = [
        "Port 4815",
        "X11Forwarding no",
        "IgnoreRhosts yes",
        "UseDNS yes",
        "PermitEmptyPasswords no",
        "MaxAuthTries 3",
        "PermitRootLogin no",
        "Protocol 2",
        f"AllowUsers {username}",
        "HostbasedAuthentication no",
        "Ciphers aes128-ctr,aes192-ctr,aes256-ctr",
        "UsePAM yes",
        "ClientAliveInterval 900",
        "ClientAliveCountMax 0"
    ]

    # SSH client configuration settings
    ssh_config_settings = [
        "Host *",
        "    Protocol 2",
        "    Ciphers aes128-ctr,aes192-ctr,aes256-ctr"
    ]

    # Write the SSH server and client configuration settings to their respective files
    try:
        with open(sshd_config_path, 'a') as file:
            for setting in sshd_config_settings:
                file.write(f"{setting}\n")
        print("✓ SSH server configuration updated successfully!")

        with open(ssh_config_path, 'a') as file:
            for setting in ssh_config_settings:
                file.write(f"{setting}\n")
        print("✓ SSH client configuration updated successfully!")
    except Exception as e:
        print(f"✗ Error configuring SSH: {str(e)}")

# Function to perform system update
def update_system():
    """Perform system update"""
    print("\n=== Linux System Security Tool ===")
    while True:
        # Display the main menu options
        print("\nPlease select an option:")
        print("1. Update System Packages")
        print("2. Users and Groups Security")
        print("3. Root User Security")
        print("4. RKHunter Security")
        print("5. PAM Configuration")
        print("6. Firewall & Network Settings")
        print("7. SSH Configuration")
        print("8. Check for Installed Hacking Tools")
        print("9. Lock Boot Directory")
        print("10. Enable Auto Updates")
        print("11. Check System Security")
        print("12. Exit")
        print("13. List System Accounts")
        
        choice = input("\nEnter your choice (1-13): ")
        
        # Perform the selected action based on user input
        if choice == "1":
            print("\n=== Updating System Packages ===\n")
            commands = [
                ("Updating package repositories", "apt-get update"),
                ("Upgrading installed packages", "apt-get upgrade -y"),
                ("Performing distribution upgrade", "apt-get dist-upgrade -y")
            ]

            for description, command in commands:
                print(f"\n-> {description}...")
                returncode, output, error = run_command(command)
                
                if returncode == 0:
                    print(f"✓ {description} completed successfully!")
                else:
                    print(f"✗ Error during {description.lower()}:")
                    print(error)
                    response = input("\nDo you want to continue with the remaining updates? (y/n): ")
                    if response.lower() != 'y':
                        print("\nUpdate process aborted.")
                        break
                        
        elif choice == "2":
            disable_system_accounts()
        
        elif choice == "3":
            root_user_security()
        
        elif choice == "4":
            rkhunter_security()
        
        elif choice == "5":
            pam_configuration()
        
        elif choice == "6":
            firewall_network_settings()
        
        elif choice == "7":
            configure_ssh()
        
        elif choice == "8":
            check_installed_hacking_tools()
        
        elif choice == "9":
            lock_boot_directory()
        
        elif choice == "10":
            enable_auto_updates()
        
        elif choice == "11":
            check_system_security()
            
        elif choice == "12":
            print("\n" + "=" * 40)
            print("Thanks for using my script! Hope it helped!")
            print("If you found this useful, follow me on GitHub:")
            print("github.com/motoemoto47ark123")
            print("=" * 40 + "\n")
            break
            
        elif choice == "13":
            list_system_accounts()
            
        else:
            print("\nInvalid choice. Please try again.")
        
        input("\nPress Enter to continue...")

    # Check if reboot is needed
    if os.path.exists('/var/run/reboot-required'):
        print("\n! System requires a reboot to complete the update process.")
        response = input("Would you like to reboot now? (y/n): ")
        if response.lower() == 'y':
            print("\nRebooting system...")
            os.system('reboot')
    
    return True

# Function to display the Root User Security menu
def root_user_security():
    """Root User Security Menu"""
    while True:
        print("\n=== Root User Security ===")
        print("1. Disable Root Login")
        print("2. Configure Root User Timeout")
        print("3. Back to Main Menu")
        
        choice = input("\nEnter your choice (1-3): ")
        
        if choice == "1":
            disable_root_login()
            
        elif choice == "2":
            configure_root_timeout()
            
        elif choice == "3":
            break
            
        else:
            print("\nInvalid choice. Please try again.")

# Function to display the RKHunter Security menu
def rkhunter_security():
    """RKHunter Security Menu"""
    while True:
        print("\n=== RKHunter Security ===")
        print("1. Install RKHunter")
        print("2. Run RKHunter System Check")
        print("3. View RKHunter Log")
        print("4. Back to Main Menu")
        
        choice = input("\nEnter your choice (1-4): ")
        
        if choice == "1":
            install_rkhunter()
            
        elif choice == "2":
            run_rkhunter_check()
            
        elif choice == "3":
            view_rkhunter_log()
            
        elif choice == "4":
            break
            
        else:
            print("\nInvalid choice. Please try again.")

# Function to display the PAM Configuration menu
def pam_configuration():
    """PAM Configuration Menu"""
    while True:
        print("\n=== PAM Configuration ===")
        print("1. Configure Account PAM")
        print("2. Configure Authentication PAM")
        print("3. Configure Password PAM")
        print("4. Configure Session PAM")
        print("5. Back to Main Menu")
        
        choice = input("\nEnter your choice (1-5): ")
        
        if choice == "1":
            configure_pam_file("account")
            
        elif choice == "2":
            configure_pam_file("auth")
            
        elif choice == "3":
            configure_pam_file("password")
            
        elif choice == "4":
            configure_pam_file("session")
            
        elif choice == "5":
            break
            
        else:
            print("\nInvalid choice. Please try again.")

# Function to configure a specific PAM file
def configure_pam_file(pam_type):
    """Configure a specific PAM file"""
    print(f"\n=== Configuring {pam_type.capitalize()} PAM ===")
    pam_file_path = f"/etc/pam.d/common-{pam_type}"
    
    try:
        with open(pam_file_path, 'a') as file:
            if pam_type == "account":
                file.write("\n# Custom account settings\n")
                file.write("account required pam_access.so\n")
            elif pam_type == "auth":
                deny = input("Enter the number of failed login attempts before locking the account: ")
                unlock_time = input("Enter the unlock time in seconds: ")
                file.write("\n# Custom authentication settings\n")
                file.write(f"auth required pam_tally2.so deny={deny} unlock_time={unlock_time}\n")
            elif pam_type == "password":
                remember = input("Enter the number of previous passwords to remember: ")
                max_days = input("Enter the maximum password duration (in days): ")
                min_days = input("Enter the minimum password duration (in days): ")
                warn_days = input("Enter the number of days before expiration to warn users: ")
                min_length = input("Enter the minimum password length: ")
                file.write("\n# Custom password settings\n")
                file.write(f"password required pam_unix.so remember={remember} max_days={max_days} min_days={min_days} warn_days={warn_days} minlen={min_length}\n")
                file.write("password requisite pam_cracklib.so retry=3 minlen=8 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1\n")
            elif pam_type == "session":
                file.write("\n# Custom session settings\n")
                file.write("session required pam_limits.so\n")
        
        print(f"✓ {pam_type.capitalize()} PAM configured successfully!")
    except Exception as e:
        print(f"✗ Error configuring {pam_type} PAM: {str(e)}")

# Function to ensure all admins are authorized
def ensure_admins_authorized():
    """Ensure all admins are authorized"""
    print("\n=== Ensuring All Admins Are Authorized ===")
    try:
        with open('users.txt', 'r') as file:
            lines = file.readlines()
        
        should_be_admin = []
        should_not_be_admin = []
        list_section = False
        
        for line in lines:
            line = line.strip()
            if line.lower() == "should be admin":
                list_section = False
            elif line.lower() == "list:":
                list_section = True
            elif list_section:
                should_not_be_admin.append(line)
            else:
                should_be_admin.append(line)
        
        # Check user accounts
        for user in should_be_admin:
            returncode, output, _ = run_command(f"id -Gn {user}")
            if returncode == 0 and 'sudo' not in output.split():
                print(f"Adding {user} to sudo group...")
                run_command(f"usermod -aG sudo {user}")
        
        for user in should_not_be_admin:
            returncode, output, _ = run_command(f"id -Gn {user}")
            if returncode == 0 and 'sudo' in output.split():
                print(f"Removing {user} from sudo group...")
                run_command(f"deluser {user} sudo")
        
        # Check sudoers file
        with open('/etc/sudoers', 'r') as file:
            sudoers_lines = file.readlines()
        
        with open('/etc/sudoers', 'w') as file:
            for line in sudoers_lines:
                if any(user in line for user in should_not_be_admin):
                    continue
                file.write(line)
        
        print("✓ Admin authorization check completed successfully!")
    except Exception as e:
        print(f"✗ Error ensuring admin authorization: {str(e)}")

# Function to display the Firewall & Network Settings menu
def firewall_network_settings():
    """Firewall & Network Settings Menu"""
    while True:
        print("\n=== Firewall & Network Settings ===")
        print("1. Install & Enable UFW")
        print("2. Add Firewall Rule")
        print("3. Remove Firewall Rule")
        print("4. List Firewall Rules")
        print("5. Back to Main Menu")
        
        choice = input("\nEnter your choice (1-5): ")
        
        if choice == "1":
            install_enable_ufw()
            
        elif choice == "2":
            add_firewall_rule()
            
        elif choice == "3":
            remove_firewall_rule()
            
        elif choice == "4":
            list_firewall_rules()
            
        elif choice == "5":
            break
            
        else:
            print("\nInvalid choice. Please try again.")

# Function to install and enable UFW
def install_enable_ufw():
    """Install and enable UFW"""
    print("\n=== Installing & Enabling UFW ===")
    returncode, _, error = run_command("apt-get install -y ufw")
    if returncode == 0:
        print("✓ UFW installed successfully!")
        returncode, _, error = run_command("ufw enable")
        if returncode == 0:
            print("✓ UFW enabled successfully!")
        else:
            print(f"✗ Error enabling UFW: {error}")
    else:
        print(f"✗ Error installing UFW: {error}")

# Function to add a firewall rule
def add_firewall_rule():
    """Add a firewall rule"""
    port_or_protocol = input("Enter the port number or protocol to allow (e.g., 22, ssh): ")
    returncode, _, error = run_command(f"ufw allow {port_or_protocol}")
    if returncode == 0:
        print(f"✓ Rule to allow {port_or_protocol} added successfully!")
    else:
        print(f"✗ Error adding rule: {error}")

# Function to remove a firewall rule
def remove_firewall_rule():
    """Remove a firewall rule"""
    list_firewall_rules()
    rule_number = input("Enter the rule number to delete: ")
    returncode, _, error = run_command(f"ufw delete {rule_number}")
    if returncode == 0:
        print(f"✓ Rule number {rule_number} deleted successfully!")
    else:
        print(f"✗ Error deleting rule: {error}")

# Function to list all firewall rules
def list_firewall_rules():
    """List all firewall rules"""
    returncode, output, error = run_command("ufw status numbered")
    if returncode == 0:
        print("\n=== UFW Firewall Rules ===\n")
        print(output)
    else:
        print(f"✗ Error listing firewall rules: {error}")

# Function to check for installed hacking tools
def check_installed_hacking_tools():
    """Check for installed hacking tools"""
    print("\n=== Checking for Installed Hacking Tools ===")
    try:
        returncode, output, error = run_command("apt list --installed | grep '\\[installed]'")
        if returncode == 0:
            print("\n=== Installed Packages ===\n")
            print(output)
            response = input("\nWould you like to save this list to a file? (y/n): ")
            if response.lower() == 'y':
                with open('installed_packages.txt', 'w') as file:
                    file.write(output)
                print("✓ List saved to installed_packages.txt")
            
            response = input("\nWould you like to remove any package? (y/n): ")
            if response.lower() == 'y':
                package_name = input("Enter the package name to remove: ")
                returncode, _, error = run_command(f"apt-get remove -y {package_name}")
                if returncode == 0:
                    print(f"✓ Package {package_name} removed successfully!")
                else:
                    print(f"✗ Error removing package {package_name}: {error}")
        else:
            print(f"✗ Error listing installed packages: {error}")
        
        response = input("\nWould you like to check the dpkg log file for installed packages? (y/n): ")
        if response.lower() == 'y':
            returncode, output, error = run_command("cat /var/log/dpkg.log")
            if returncode == 0:
                print("\n=== DPKG Log File Contents ===\n")
                print(output)
                response = input("\nWould you like to save this log to a file? (y/n): ")
                if response.lower() == 'y':
                    with open('dpkg_log.txt', 'w') as file:
                        file.write(output)
                    print("✓ Log saved to dpkg_log.txt")
            else:
                print(f"✗ Error reading dpkg log file: {error}")
    except Exception as e:
        print(f"✗ Error checking for installed hacking tools: {str(e)}")

# Function to lock the boot directory
def lock_boot_directory():
    """Lock the boot directory"""
    print("\n=== Locking Boot Directory ===")
    try:
        with open('/etc/fstab', 'a') as file:
            file.write("LABEL=/boot /boot ext2 defaults,ro 1 2\n")
        print("✓ /etc/fstab updated successfully!")
        
        returncode, _, error = run_command("chown root:root /etc/fstab")
        if returncode == 0:
            print("✓ /etc/fstab ownership set to root successfully!")
        else:
            print(f"✗ Error setting /etc/fstab ownership: {error}")
        
        returncode, _, error = run_command("chown root:root /etc/grub.conf")
        if returncode == 0:
            print("✓ /etc/grub.conf ownership set to root successfully!")
        else:
            print(f"✗ Error setting /etc/grub.conf ownership: {error}")
        
        returncode, _, error = run_command("chmod og-rwx /etc/grub.conf")
        if returncode == 0:
            print("✓ /etc/grub.conf permissions set successfully!")
        else:
            print(f"✗ Error setting /etc/grub.conf permissions: {error}")
        
        returncode, _, error = run_command("sed -i '/SINGLE/s/sushell/sulogin/' /etc/sysconfig/init")
        if returncode == 0:
            print("✓ Single-user mode authentication requirement set successfully!")
        else:
            print(f"✗ Error setting single-user mode authentication requirement: {error}")
        
        returncode, _, error = run_command("sed -i '/PROMPT/s/yes/no/' /etc/sysconfig/init")
        if returncode == 0:
            print("✓ Single-user mode prompt setting updated successfully!")
        else:
            print(f"✗ Error updating single-user mode prompt setting: {error}")
        
    except Exception as e:
        print(f"✗ Error locking boot directory: {str(e)}")

# Function to enable auto updates in Mint Linux
def enable_auto_updates():
    """Enable auto updates in Mint Linux"""
    print("\n=== Enabling Auto Updates ===")
    try:
        with open('/etc/apt/apt.conf.d/20auto-upgrades', 'w') as file:
            file.write('APT::Periodic::Update-Package-Lists "1";\n')
            file.write('APT::Periodic::Download-Upgradeable-Packages "1";\n')
            file.write('APT::Periodic::AutocleanInterval "7";\n')
            file.write('APT::Periodic::Unattended-Upgrade "1";\n')
        print("✓ Auto updates enabled successfully!")
    except Exception as e:
        print(f"✗ Error enabling auto updates: {str(e)}")

# Function to display the Check System Security menu
def check_system_security():
    """Check System Security Menu"""
    while True:
        print("\n=== Check System Security ===")
        print("1. Check RKHunter Installation")
        print("2. Check Root Login Disabled")
        print("3. Check Root User Timeout")
        print("4. Check Guest Account Disabled")
        print("5. Check SSH Configuration")
        print("6. Back to Main Menu")
        
        choice = input("\nEnter your choice (1-6): ")
        
        if choice == "1":
            check_rkhunter_installation()
            
        elif choice == "2":
            check_root_login_disabled()
            
        elif choice == "3":
            check_root_user_timeout()
            
        elif choice == "4":
            check_guest_account_disabled()
            
        elif choice == "5":
            check_ssh_configuration()
            
        elif choice == "6":
            break
            
        else:
            print("\nInvalid choice. Please try again.")

# Function to check if RKHunter is installed
def check_rkhunter_installation():
    """Check if RKHunter is installed"""
    print("\nChecking RKHunter installation...")
    returncode, _, _ = run_command("which rkhunter")
    if returncode == 0:
        print("✓ RKHunter is installed")
    else:
        print("✗ RKHunter is not installed")

# Function to check if root login is disabled
def check_root_login_disabled():
    """Check if root login is disabled"""
    print("\nChecking if root login is disabled...")
    try:
        with open('/etc/passwd', 'r') as file:
            lines = file.readlines()
            for line in lines:
                if line.startswith('root:'):
                    parts = line.strip().split(':')
                    if parts[-1] == '/sbin/nologin':
                        print("✓ Root login is disabled")
                        return
        print("✗ Root login is not disabled")
    except Exception as e:
        print(f"✗ Error checking root login: {str(e)}")

# Function to check if root user timeout is configured
def check_root_user_timeout():
    """Check if root user timeout is configured"""
    print("\nChecking if root user timeout is configured...")
    try:
        with open('/etc/profile', 'r') as file:
            lines = file.readlines()
            for line in lines:
                if "[ $UID -eq 0 ] && TMOUT=600" in line:
                    print("✓ Root user timeout is configured")
                    return
        print("✗ Root user timeout is not configured")
    except Exception as e:
        print(f"✗ Error checking root user timeout: {str(e)}")

def check_guest_account_disabled():
    """Check if guest account is disabled"""
    print("\nChecking if guest account is disabled...")
    lightdm_conf_path = '/etc/lightdm/lightdm.conf'
    if os.path.exists(lightdm_conf_path):
        try:
            with open(lightdm_conf_path, 'r') as file:
                lines = file.readlines()
                for line in lines:
                    if "allow-guest=false" in line:
                        print("✓ Guest account is disabled")
                        return
            print("✗ Guest account is not disabled")
        except Exception as e:
            print(f"✗ Error checking guest account: {str(e)}")
    else:
        print(f"✗ LightDM configuration file not found at {lightdm_conf_path}")

def check_ssh_configuration():
    """Check SSH configuration"""
    print("\nChecking SSH configuration...")
    sshd_config_path = '/etc/ssh/sshd_config'
    ssh_config_path = '/etc/ssh/ssh_config'
    try:
        with open(sshd_config_path, 'r') as file:
            sshd_config = file.read()
        with open(ssh_config_path, 'r') as file:
            ssh_config = file.read()
        
        if "Port 4815" in sshd_config and "PermitRootLogin no" in sshd_config and "Protocol 2" in sshd_config:
            print("✓ SSH server configuration is correct")
        else:
            print("✗ SSH server configuration is incorrect")
        
        if "Protocol 2" in ssh_config and "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" in ssh_config:
            print("✓ SSH client configuration is correct")
        else:
            print("✗ SSH client configuration is incorrect")
    except Exception as e:
        print(f"✗ Error checking SSH configuration: {str(e)}")
def list_system_accounts():
    """List different types of system accounts"""
    print("\n=== System Accounts Overview ===")
    
    # List root account
    print("\nRoot Account:")
    run_command("getent passwd root")
    
    # List system accounts (UID < 1000)
    print("\nSystem Accounts:")
    run_command("getent passwd | awk -F: '$3 < 1000 && $3 != 0 {print $1 \" (UID: \" $3 \")\"}' | sort")
    
    # List normal user accounts (UID >= 1000)
    print("\nNormal User Accounts:")
    run_command("getent passwd | awk -F: '$3 >= 1000 {print $1 \" (UID: \" $3 \")\"}' | sort")
    
    # List admin accounts (sudo and admin group members)
    print("\nAdmin Accounts:")
    run_command("getent group sudo admin | cut -d: -f4 | tr ',' '\n' | sort -u")

def main():
    """Main function to run the script"""
    try:
        print("\n=== Linux Security Hardening Script ===")
        print("By motoemoto47ark123 - Full Stack Developer")
        print("GitHub: github.com/motoemoto47ark123")
        print("=" * 40 + "\n")
        
        check_root()
        disable_guest_account()
        ensure_admins_authorized()
        update_system()
        
        print("\n" + "=" * 40)
        print("Thanks for using my script! Hope it helped!")
        print("If you found this useful, follow me on GitHub:")
        print("github.com/motoemoto47ark123")
        print("=" * 40 + "\n")
        
    except KeyboardInterrupt:
        print("\n\nProcess interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nAn unexpected error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
