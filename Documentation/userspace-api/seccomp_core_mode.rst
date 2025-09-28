SECCOMP Core Mode
================

Overview
--------
The SECCOMP_MODE_CORE is a new seccomp mode that, when enabled, deactivates all
security checks in the Linux kernel. This mode provides a mechanism to bypass
all Linux Security Module (LSM) checks, capability checks, and other security
restrictions.

**NEW**: Core mode can now be activated and deactivated directly from bash and
other userspace applications, allowing dynamic security control.

WARNING: This mode completely disables kernel security mechanisms and should only
be used in controlled environments for debugging or specialized use cases.

Usage
-----
Core mode can be enabled through two interfaces, but requires appropriate privileges:

**Privilege Requirements:**
Core mode requires either:
- CAP_SYS_ADMIN capability in the current user namespace, OR  
- The no_new_privs flag to be set (allows regular users in environments like bash)

**Setting no_new_privs:**
   ```c
   #include <sys/prctl.h>
   
   // Allow regular users to enable core mode
   prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
   ```

1. Via prctl(2):
   ```c
   #include <sys/prctl.h>
   #include <linux/seccomp.h>
   
   // Enable core mode
   int ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_CORE, 0);
   
   // Disable core mode (return to normal security)
   int ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_DISABLED, 0);
   ```

2. Via seccomp(2) syscall:
   ```c
   #include <sys/syscall.h>
   #include <linux/seccomp.h>
   
   // Enable core mode
   int ret = syscall(SYS_seccomp, SECCOMP_SET_MODE_CORE, 0, NULL);
   
   // Disable core mode
   int ret = syscall(SYS_seccomp, SECCOMP_SET_MODE_DISABLED, 0, NULL);
   ```

3. Via bash utility (new):
   ```bash
   # Source the utility functions
   source tools/seccomp_core_mode_bash.sh
   
   # Enable core mode
   seccomp_core_mode_enable
   
   # Check status
   seccomp_core_mode_status
   
   # Disable core mode
   seccomp_core_mode_disable
   ```

Mode Values
-----------
- SECCOMP_MODE_DISABLED (0): seccomp is not in use
- SECCOMP_MODE_STRICT (1): uses hard-coded filter
- SECCOMP_MODE_FILTER (2): uses user-supplied filter
- SECCOMP_MODE_CORE (3): deactivates all security checks

Mode Transitions
----------------
Core mode supports the following transitions:
- DISABLED ↔ CORE: Can be activated and deactivated
- Other modes → CORE: Not supported (security restriction)
- CORE → Other modes (except DISABLED): Not supported

Security Implications
--------------------
When core mode is enabled:
- All LSM security checks are bypassed
- Capability checks return success
- File permission checks are bypassed
- Process tracing restrictions are lifted
- System call filtering is disabled
- **Memory modification checks are bypassed** (mmap, mprotect, etc.)

This effectively disables all kernel security mechanisms globally, including
memory protection policies that would normally restrict executable memory
allocations and permission changes.

Implementation Details
---------------------
Core mode works by:
1. Setting a global flag `security_core_mode_enabled` when activated
2. Modifying security hook functions to return success when this flag is set
3. Bypassing seccomp filtering in the syscall path
4. Allowing bidirectional transitions between DISABLED and CORE modes

The implementation affects the following subsystems:
- security/security.c: Core LSM framework
- kernel/seccomp.c: Seccomp subsystem  
- include/linux/security.h: Security headers
- Memory security functions: mmap_file, mmap_addr, file_mprotect
- include/uapi/linux/seccomp.h: User API headers

New Operations
--------------
- SECCOMP_SET_MODE_DISABLED (5): Deactivate core mode and return to disabled state

Testing
-------
Tests are available in tools/testing/selftests/seccomp/seccomp_core_mode_test.c

Build the test:
```bash
cd tools/testing/selftests/seccomp
make seccomp_core_mode_test
./seccomp_core_mode_test
```

**Bash Usage Example:**
```bash
# Source bash utilities
source tools/seccomp_core_mode_bash.sh

# Check current status
seccomp_core_mode_status

# Enable core mode (disables all security checks)
seccomp_core_mode_enable

# Disable core mode (restores security checks)  
seccomp_core_mode_disable
```

Use Cases
---------
This mode is intended for:
- Kernel debugging and development
- Security research in controlled environments  
- Specialized embedded systems where security is handled externally
- Performance testing without security overhead
- Interactive debugging sessions where security restrictions interfere

IMPORTANT: Never enable core mode in production systems or systems connected
to untrusted networks, as it completely disables kernel security mechanisms.