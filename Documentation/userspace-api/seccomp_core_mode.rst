SECCOMP Core Mode
================

Overview
--------
The SECCOMP_MODE_CORE is a new seccomp mode that, when enabled, deactivates all
security checks in the Linux kernel. This mode provides a mechanism to bypass
all Linux Security Module (LSM) checks, capability checks, and other security
restrictions.

WARNING: This mode completely disables kernel security mechanisms and should only
be used in controlled environments for debugging or specialized use cases.

Usage
-----
Core mode can be enabled through two interfaces:

1. Via prctl(2):
   ```c
   #include <sys/prctl.h>
   #include <linux/seccomp.h>
   
   int ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_CORE, 0);
   ```

2. Via seccomp(2) syscall:
   ```c
   #include <sys/syscall.h>
   #include <linux/seccomp.h>
   
   int ret = syscall(SYS_seccomp, SECCOMP_SET_MODE_CORE, 0, NULL);
   ```

Mode Values
-----------
- SECCOMP_MODE_DISABLED (0): seccomp is not in use
- SECCOMP_MODE_STRICT (1): uses hard-coded filter
- SECCOMP_MODE_FILTER (2): uses user-supplied filter
- SECCOMP_MODE_CORE (3): deactivates all security checks

Security Implications
--------------------
When core mode is enabled:
- All LSM security checks are bypassed
- Capability checks return success
- File permission checks are bypassed
- Process tracing restrictions are lifted
- System call filtering is disabled

This effectively disables all kernel security mechanisms globally.

Implementation Details
---------------------
Core mode works by:
1. Setting a global flag `security_core_mode_enabled` when activated
2. Modifying security hook functions to return success when this flag is set
3. Bypassing seccomp filtering in the syscall path

The implementation affects the following subsystems:
- security/security.c: Core LSM framework
- kernel/seccomp.c: Seccomp subsystem
- include/linux/security.h: Security headers
- include/uapi/linux/seccomp.h: User API headers

Testing
-------
Tests are available in tools/testing/selftests/seccomp/seccomp_core_mode_test.c

Build the test:
```bash
cd tools/testing/selftests/seccomp
make seccomp_core_mode_test
./seccomp_core_mode_test
```

Use Cases
---------
This mode is intended for:
- Kernel debugging and development
- Security research in controlled environments  
- Specialized embedded systems where security is handled externally
- Performance testing without security overhead

IMPORTANT: Never enable core mode in production systems or systems connected
to untrusted networks, as it completely disables kernel security mechanisms.