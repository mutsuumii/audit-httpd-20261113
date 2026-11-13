# Unsafe setuid/privilege drop
# CWE-273 | Severity: HIGH
# File: support/suexec.c line 545

**Risk:** Privilege drop return value not checked. Failed setuid() leaves process running as root when it expects to be unprivileged.

**Fix:** Always check setuid() return: if (setuid(uid) != 0) { perror('setuid'); exit(1); }
