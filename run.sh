#!/bin/bash

# Web Penetration Testing Tool Runner
# Developed by: Saudi Linux
# Email: SaudiLinux7@gmail.com

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Print banner
echo -e "${RED}"
echo "██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗████████╗"
echo "██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝"
echo "██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ███████╗   ██║   "
echo "██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ╚════██║   ██║   "
echo "██║     ███████╗██║ ╚████║   ██║   ███████╗███████║   ██║   "
echo "╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝   "
echo -e "${NC}"
echo -e "${CYAN}Web Penetration Testing Tool${NC}"
echo -e "${CYAN}Developed by: Saudi Linux${NC}"
echo -e "${CYAN}Email: SaudiLinux7@gmail.com${NC}"
echo -e "${YELLOW}Version: 1.0${NC}"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed.${NC}"
    echo "Please install Python 3.8 or higher and try again."
    exit 1
fi

# Check if requirements are installed
echo -e "${CYAN}Checking requirements...${NC}"
if ! python3 -c "import requests" &> /dev/null; then
    echo -e "${YELLOW}Installing required packages...${NC}"
    pip3 install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error installing requirements. Please run 'pip3 install -r requirements.txt' manually.${NC}"
        exit 1
    fi
fi

# Make sure the script is executable
chmod +x run.py

# Get URL from user if not provided as argument
url=$1
if [ -z "$url" ]; then
    echo ""
    read -p "Enter target URL: " url
fi

# Run the tool
echo ""
echo -e "${CYAN}Running scan on $url...${NC}"
echo ""

python3 run.py -u "$url" -v

echo ""
echo -e "${GREEN}Scan completed.${NC}"