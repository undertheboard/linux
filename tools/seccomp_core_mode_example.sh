#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Example script demonstrating SECCOMP core mode activation/deactivation in bash

echo "SECCOMP Core Mode Example"
echo "========================"
echo

# Source the core mode utilities
SCRIPT_DIR="$(dirname "${BASH_SOURCE[0]}")"
source "$SCRIPT_DIR/seccomp_core_mode_bash.sh"

echo "This example demonstrates core mode activation and deactivation."
echo "WARNING: This will temporarily disable all kernel security checks!"
echo

# Show initial status
echo "=== Initial Status ==="
seccomp_core_mode_status
echo

# Prompt for user confirmation
read -p "Do you want to proceed with core mode demonstration? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

echo "=== Activating Core Mode ==="
if seccomp_core_mode_enable; then
    echo "Core mode is now active!"
    echo
    
    echo "=== Status Check ==="
    seccomp_core_mode_status
    echo
    
    echo "=== Demonstrating Security Bypass ==="
    echo "Attempting operations that would normally be restricted..."
    
    # Try some operations that demonstrate security bypass
    echo "Creating executable memory mapping..."
    if python3 -c "
import mmap
import os
try:
    # Create an anonymous memory mapping with executable permissions
    mem = mmap.mmap(-1, 4096, mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    print('SUCCESS: Created executable memory mapping')
    mem.close()
except Exception as e:
    print(f'INFO: Memory mapping failed: {e}')
" 2>/dev/null; then
        echo "Memory operations succeeded (security bypassed)"
    else
        echo "Memory operations may have been restricted (expected in containerized environment)"
    fi
    
    echo
    echo "=== Deactivating Core Mode ==="
    if seccomp_core_mode_disable; then
        echo "Core mode deactivated - security checks restored"
        echo
        
        echo "=== Final Status Check ==="
        seccomp_core_mode_status
        echo
        
        echo "=== Demonstration Complete ==="
        echo "Successfully demonstrated core mode activation and deactivation!"
    else
        echo "ERROR: Failed to deactivate core mode"
        exit 1
    fi
else
    echo "ERROR: Failed to activate core mode"
    echo "This may be expected if running on a kernel without core mode support"
    exit 1
fi

echo
echo "Example completed successfully."
echo "Note: In a kernel with core mode support, all security checks would have been"
echo "temporarily bypassed during the demonstration."