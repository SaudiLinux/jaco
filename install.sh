#!/bin/bash

# Web Penetration Testing Tool - Installation Script
# Developed by: Saudi Linux
# Email: SaudiLinux7@gmail.com

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Print banner
echo -e "${CYAN}"
echo "Web Penetration Testing Tool - Installation"
echo "Developed by: Saudi Linux"
echo "Email: SaudiLinux7@gmail.com"
echo -e "${NC}"
echo ""

# Check if script is run as root
if [ "$(id -u)" -eq 0 ]; then
    echo -e "${YELLOW}Running as root. This will install packages system-wide.${NC}"
else
    echo -e "${YELLOW}Running as regular user. This will install packages in user mode.${NC}"
fi

# Check if Python is installed
echo -e "${CYAN}Checking Python installation...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed.${NC}"
    echo "Please install Python 3.8 or higher using your package manager:"
    echo "  For Debian/Ubuntu: sudo apt install python3 python3-pip"
    echo "  For Fedora: sudo dnf install python3 python3-pip"
    echo "  For Arch Linux: sudo pacman -S python python-pip"
    exit 1
else
    python_version=$(python3 --version 2>&1 | cut -d" " -f2)
    echo -e "${GREEN}Found Python $python_version${NC}"
fi

# Check pip installation
echo -e "${CYAN}Checking pip installation...${NC}"
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}Error: pip3 is not installed.${NC}"
    echo "Please install pip3 using your package manager:"
    echo "  For Debian/Ubuntu: sudo apt install python3-pip"
    echo "  For Fedora: sudo dnf install python3-pip"
    echo "  For Arch Linux: sudo pacman -S python-pip"
    exit 1
else
    echo -e "${GREEN}pip3 is installed.${NC}"
fi

# Install required packages
echo -e "\n${CYAN}Installing required packages...${NC}"
pip3 install -r requirements.txt
if [ $? -ne 0 ]; then
    echo -e "${RED}Error installing requirements. Please check your internet connection${NC}"
    echo -e "${RED}and try running 'pip3 install -r requirements.txt' manually.${NC}"
    exit 1
else
    echo -e "${GREEN}All required packages installed successfully.${NC}"
fi

# Make scripts executable
echo -e "\n${CYAN}Making scripts executable...${NC}"
chmod +x run.py run.sh
echo -e "${GREEN}Scripts are now executable.${NC}"

# Create desktop shortcut (if desktop environment is detected)
if [ -d "$HOME/Desktop" ]; then
    echo -e "\n${CYAN}Creating desktop shortcut...${NC}"
    
    # Get absolute path to the script directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Create .desktop file
    cat > "$HOME/Desktop/web-pentest-tool.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Web Penetration Testing Tool
Comment=Tool for web penetration testing
Exec=bash "$SCRIPT_DIR/run.sh"
Path=$SCRIPT_DIR
Terminal=true
Categories=Security;Network;
EOF
    
    # Make it executable
    chmod +x "$HOME/Desktop/web-pentest-tool.desktop"
    
    echo -e "${GREEN}Desktop shortcut created.${NC}"
fi

# Create symlink in /usr/local/bin if running as root
if [ "$(id -u)" -eq 0 ]; then
    echo -e "\n${CYAN}Creating system-wide command...${NC}"
    
    # Get absolute path to the script directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Create wrapper script
    cat > /usr/local/bin/webpentest << EOF
#!/bin/bash
bash "$SCRIPT_DIR/run.sh" "\$@"
EOF
    
    # Make it executable
    chmod +x /usr/local/bin/webpentest
    
    echo -e "${GREEN}System-wide command 'webpentest' created.${NC}"
    echo -e "${GREEN}You can now run the tool from anywhere using the 'webpentest' command.${NC}"
fi

echo -e "\n${GREEN}Installation completed successfully!${NC}"
echo -e "${GREEN}You can now run the tool using:${NC}"
echo -e "  ${CYAN}./run.sh${NC}"

if [ -d "$HOME/Desktop" ]; then
    echo -e "  ${CYAN}Or using the desktop shortcut${NC}"
fi

if [ "$(id -u)" -eq 0 ]; then
    echo -e "  ${CYAN}Or by typing 'webpentest' in any terminal${NC}"
fi

echo -e "\n${GREEN}Thank you for installing Web Penetration Testing Tool!${NC}"