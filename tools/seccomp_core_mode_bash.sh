#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Bash utility functions for SECCOMP core mode activation/deactivation
# 
# Usage:
#   source seccomp_core_mode_bash.sh
#   seccomp_core_mode_enable
#   seccomp_core_mode_disable
#   seccomp_core_mode_status

# Check if the core mode test binary exists and is executable
CORE_MODE_TEST_PATH="${BASH_SOURCE%/*}/../testing/selftests/seccomp/seccomp_core_mode_test"
if [[ ! -x "$CORE_MODE_TEST_PATH" ]]; then
    # Try alternative paths
    for path in "./seccomp_core_mode_test" "/usr/bin/seccomp_core_mode_test" "./tools/testing/selftests/seccomp/seccomp_core_mode_test"; do
        if [[ -x "$path" ]]; then
            CORE_MODE_TEST_PATH="$path"
            break
        fi
    done
fi

# Create a simple C program that can be compiled and used for core mode operations
create_core_mode_helper() {
    local helper_file="/tmp/seccomp_core_mode_helper.c"
    cat > "$helper_file" << 'EOF'
#define _GNU_SOURCE
#include <errno.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#ifndef SECCOMP_MODE_CORE
#define SECCOMP_MODE_CORE 3
#endif

#ifndef SECCOMP_SET_MODE_CORE
#define SECCOMP_SET_MODE_CORE 4
#endif

#ifndef SECCOMP_SET_MODE_DISABLED
#define SECCOMP_SET_MODE_DISABLED 5
#endif

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <enable|disable|status>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "status") == 0) {
        int mode = prctl(PR_GET_SECCOMP);
        if (mode < 0) {
            perror("prctl(PR_GET_SECCOMP)");
            return 1;
        }
        printf("%d\n", mode);
        return 0;
    }

    /* Set no_new_privs to allow core mode for regular users */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fprintf(stderr, "Warning: Failed to set no_new_privs (errno=%d)\n", errno);
    }

    if (strcmp(argv[1], "enable") == 0) {
        /* Try to enable core mode */
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_CORE, 0) == 0) {
            printf("Core mode enabled\n");
            return 0;
        } else {
            fprintf(stderr, "Failed to enable core mode (errno=%d): %s\n", errno, strerror(errno));
            return 1;
        }
    } else if (strcmp(argv[1], "disable") == 0) {
        /* Try to disable core mode */
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_DISABLED, 0) == 0) {
            printf("Core mode disabled\n");
            return 0;
        } else {
            fprintf(stderr, "Failed to disable core mode (errno=%d): %s\n", errno, strerror(errno));
            return 1;
        }
    } else {
        fprintf(stderr, "Invalid command: %s\n", argv[1]);
        return 1;
    }
}
EOF
    
    # Compile the helper
    local helper_binary="/tmp/seccomp_core_mode_helper"
    if gcc -o "$helper_binary" "$helper_file" 2>/dev/null; then
        echo "$helper_binary"
        return 0
    else
        echo ""
        return 1
    fi
}

# Global variable to store helper path
SECCOMP_HELPER=""

# Initialize helper
init_seccomp_helper() {
    if [[ -z "$SECCOMP_HELPER" ]]; then
        SECCOMP_HELPER=$(create_core_mode_helper)
        if [[ -z "$SECCOMP_HELPER" ]]; then
            echo "Error: Failed to create seccomp core mode helper" >&2
            return 1
        fi
    fi
    return 0
}

# Enable core mode
seccomp_core_mode_enable() {
    init_seccomp_helper || return 1
    
    echo "Enabling SECCOMP core mode..."
    if "$SECCOMP_HELPER" enable; then
        echo "SECCOMP core mode enabled successfully"
        echo "WARNING: All kernel security checks are now bypassed!"
        return 0
    else
        echo "Failed to enable SECCOMP core mode"
        return 1
    fi
}

# Disable core mode
seccomp_core_mode_disable() {
    init_seccomp_helper || return 1
    
    echo "Disabling SECCOMP core mode..."
    if "$SECCOMP_HELPER" disable; then
        echo "SECCOMP core mode disabled successfully"
        echo "Kernel security checks restored"
        return 0
    else
        echo "Failed to disable SECCOMP core mode"
        return 1
    fi
}

# Check core mode status
seccomp_core_mode_status() {
    init_seccomp_helper || return 1
    
    local mode
    mode=$("$SECCOMP_HELPER" status 2>/dev/null)
    local ret=$?
    
    if [[ $ret -eq 0 ]]; then
        case "$mode" in
            0) echo "SECCOMP mode: DISABLED" ;;
            1) echo "SECCOMP mode: STRICT" ;;
            2) echo "SECCOMP mode: FILTER" ;;
            3) echo "SECCOMP mode: CORE (all security checks bypassed)" ;;
            *) echo "SECCOMP mode: UNKNOWN ($mode)" ;;
        esac
        return 0
    else
        echo "Failed to get SECCOMP status"
        return 1
    fi
}

# Cleanup function
seccomp_core_mode_cleanup() {
    if [[ -n "$SECCOMP_HELPER" && -f "$SECCOMP_HELPER" ]]; then
        rm -f "$SECCOMP_HELPER" "${SECCOMP_HELPER%.c}.c" 2>/dev/null
    fi
}

# Set cleanup trap
trap seccomp_core_mode_cleanup EXIT

echo "SECCOMP core mode bash utilities loaded."
echo "Available functions:"
echo "  seccomp_core_mode_enable  - Enable core mode"
echo "  seccomp_core_mode_disable - Disable core mode"
echo "  seccomp_core_mode_status  - Show current status"
echo ""
echo "WARNING: Core mode completely disables kernel security mechanisms!"
echo "Only use in controlled environments for debugging or testing."