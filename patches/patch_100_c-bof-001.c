# Buffer overflow via unsafe string function
# CWE-120 | Severity: CRITICAL
# File: modules/filters/mod_xml2enc.c line 305

**Risk:** strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
