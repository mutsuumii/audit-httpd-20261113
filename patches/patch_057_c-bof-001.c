# Buffer overflow via unsafe string function
# CWE-120 | Severity: CRITICAL
# File: modules/aaa/mod_authn_socache.c line 274

**Risk:** strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
