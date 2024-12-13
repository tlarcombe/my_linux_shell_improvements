#!/bin/bash

# Installation script for ShellAI

# Check for required dependencies
check_dependencies() {
    local deps=("python3" "pip" "nano")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        echo "Missing dependencies: ${missing[*]}"
        echo "Please install them first."
        exit 1
    fi
}

# Install Python dependencies
install_python_deps() {
    echo "Installing Python dependencies..."
    pip install --user requests pyyaml
}

# Create directories and copy files
setup_files() {
    local script_dir="/usr/local/bin/sh"
    local config_dir="$HOME/.config/shellai"
    
    # Create directories
    sudo mkdir -p "$
