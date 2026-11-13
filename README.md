# Security audit: apache/httpd

Date: 2026-11-13 | Auditor: [mutsuumii](https://github.com/mutsuumii)

## Summary

Found 109 issue(s): 10 critical, 99 high.

## Findings

### 1. [CRITICAL] Format string vulnerability

**CWE-134** | `support/suexec.c` line 392

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
log_err("user mismatch (%s instead of %s)\n", pw->pw_name, AP_HTTPD_USER);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 2. [CRITICAL] Format string vulnerability

**CWE-134** | `support/suexec.c` line 397

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
log_err("user mismatch (%s instead of %s)\n", pw->pw_name, AP_HTTPD_USER);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 3. [CRITICAL] Format string vulnerability

**CWE-134** | `support/suexec.c` line 429

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
log_err("invalid target user name: (%s)\n", target_uname);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 4. [CRITICAL] Format string vulnerability

**CWE-134** | `support/suexec.c` line 443

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
log_err("invalid target user id: (%s)\n", target_uname);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 5. [CRITICAL] Format string vulnerability

**CWE-134** | `support/suexec.c` line 453

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
log_err("invalid target group name: (%s)\n", target_gname);
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 6. [CRITICAL] Format string vulnerability

**CWE-134** | `support/suexec.c` line 484

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
log_err("failed to setup bs2000 environment for user %s: %s\n",
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 7. [HIGH] Missing NULL check after allocation

**CWE-476** | `support/suexec.c` line 247

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
cleanenv[cidx] = strdup("PATH=" AP_SAFE_PATH);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 8. [HIGH] Missing NULL check after allocation

**CWE-476** | `support/suexec.c` line 505

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
actual_uname = strdup(pw->pw_name);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 9. [HIGH] Missing NULL check after allocation

**CWE-476** | `support/suexec.c` line 506

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
target_homedir = strdup(pw->pw_dir);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 10. [HIGH] Unsafe setuid/privilege drop

**CWE-273** | `support/suexec.c` line 545

Privilege drop return value not checked. Failed setuid() leaves process running as root when it expects to be unprivileged.

```
if (((setgid(gid)) != 0) || (initgroups(actual_uname, gid) != 0)) {
```

**Fix:** Always check setuid() return: if (setuid(uid) != 0) { perror('setuid'); exit(1); }
---

### 11. [HIGH] Unsafe setuid/privilege drop

**CWE-273** | `support/suexec.c` line 554

Privilege drop return value not checked. Failed setuid() leaves process running as root when it expects to be unprivileged.

```
if ((setuid(uid)) != 0) {
```

**Fix:** Always check setuid() return: if (setuid(uid) != 0) { perror('setuid'); exit(1); }
---

### 12. [HIGH] Unsafe setuid/privilege drop

**CWE-273** | `support/suexec.c` line 555

Privilege drop return value not checked. Failed setuid() leaves process running as root when it expects to be unprivileged.

```
log_err("failed to setuid (%lu: %s): %s\n",
```

**Fix:** Always check setuid() return: if (setuid(uid) != 0) { perror('setuid'); exit(1); }
---

### 13. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/http/http_request.c` line 537

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
new = (request_rec *) apr_pcalloc(r->pool, sizeof(request_rec));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 14. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/filters/mod_proxy_html.c` line 890

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
fctx = f->ctx = apr_pcalloc(f->r->pool, sizeof(saxctxt));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 15. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/filters/mod_proxy_html.c` line 1067

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
proxy_html_conf *ret = apr_pcalloc(pool, sizeof(proxy_html_conf));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 16. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/md/md_result.c` line 34

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
char *d = apr_pstrdup(p, s);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 17. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/md/md_result.c` line 43

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
result = apr_pcalloc(p, sizeof(*result));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 18. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/md/md_result.c` line 71

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
md_result_activity_setn(result, activity? apr_pstrdup(result->p, activity) : NULL);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 19. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/md/md_result.c` line 106

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
result->detail = apr_pstrdup(result->p, detail);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 20. [HIGH] Use-after-free pattern

**CWE-416** | `modules/ssl/ssl_ct_sct.c` line 47

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
EVP_MD_CTX_free(ctx);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 21. [HIGH] Use-after-free pattern

**CWE-416** | `modules/ssl/ssl_ct_sct.c` line 246

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
OPENSSL_free(der_buf);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 22. [HIGH] Use-after-free pattern

**CWE-416** | `modules/ssl/ssl_ct_sct.c` line 260

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
free(orig_mem);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 23. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/ssl/ssl_ct_sct.c` line 220

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
mem = ap_malloc(avail);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 24. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `modules/dav/main/mod_dav.c` line 2110

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
strcpy(s, elts[i].key);
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 25. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/dav/main/mod_dav.c` line 141

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
newconf = (dav_server_conf *)apr_pcalloc(p, sizeof(*newconf));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 26. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/dav/main/mod_dav.c` line 155

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
newconf = (dav_server_conf *)apr_pcalloc(p, sizeof(*newconf));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 27. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/dav/main/mod_dav.c` line 168

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
conf = (dav_dir_conf *)apr_pcalloc(p, sizeof(*conf));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 28. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/dav/main/mod_dav.c` line 189

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
dav_dir_conf *newconf = (dav_dir_conf *)apr_pcalloc(p, sizeof(*newconf));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 29. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/dav/main/mod_dav.c` line 935

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
range = apr_pstrdup(r->pool, range_c);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 30. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/dav/main/mod_dav.c` line 1398

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
resp = apr_pcalloc(wres->pool, sizeof(*resp));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 31. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/dav/main/mod_dav.c` line 1399

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
resp->href = apr_pstrdup(wres->pool, wres->resource->uri);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 32. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/dav/main/mod_dav.c` line 3057

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
apr_pstrdup(r->pool, auth));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 33. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/dav/main/mod_dav.c` line 3476

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
lock->auth_user = apr_pstrdup(r->pool, r->user);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 34. [HIGH] Missing NULL check after allocation

**CWE-476** | `support/firehose.c` line 205

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
rec = apr_pcalloc(pool, sizeof(uuid_rec));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 35. [HIGH] Missing NULL check after allocation

**CWE-476** | `support/firehose.c` line 208

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
rec->uuid = apr_pstrdup(pool, header->uuid);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 36. [HIGH] Missing NULL check after allocation

**CWE-476** | `support/firehose.c` line 674

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
file = apr_pcalloc(pool, sizeof(file_rec));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 37. [HIGH] Missing NULL check after allocation

**CWE-476** | `support/firehose.c` line 721

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
rec = apr_pcalloc(pchild, sizeof(uuid_rec));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 38. [HIGH] Missing NULL check after allocation

**CWE-476** | `support/firehose.c` line 750

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
filter = apr_pcalloc(pchild, sizeof(filter_rec));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 39. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/arch/unix/mod_privileges.c` line 35

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
return apr_pstrdup(cmd->pool, msgbuf); \
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 40. [HIGH] Unsafe setuid/privilege drop

**CWE-273** | `modules/arch/unix/mod_privileges.c` line 156

Privilege drop return value not checked. Failed setuid() leaves process running as root when it expects to be unprivileged.

```
if (cfg->uid && (setuid(ap_unixd_config.user_id) == -1)) {
```

**Fix:** Always check setuid() return: if (setuid(uid) != 0) { perror('setuid'); exit(1); }
---

### 41. [HIGH] Unsafe setuid/privilege drop

**CWE-273** | `modules/arch/unix/mod_privileges.c` line 160

Privilege drop return value not checked. Failed setuid() leaves process running as root when it expects to be unprivileged.

```
if (cfg->gid && (setgid(ap_unixd_config.group_id) == -1)) {
```

**Fix:** Always check setuid() return: if (setuid(uid) != 0) { perror('setuid'); exit(1); }
---

### 42. [HIGH] Unsafe setuid/privilege drop

**CWE-273** | `modules/arch/unix/mod_privileges.c` line 265

Privilege drop return value not checked. Failed setuid() leaves process running as root when it expects to be unprivileged.

```
if (cfg->uid && (setuid(cfg->uid) == -1)) {
```

**Fix:** Always check setuid() return: if (setuid(uid) != 0) { perror('setuid'); exit(1); }
---

### 43. [HIGH] Unsafe setuid/privilege drop

**CWE-273** | `modules/arch/unix/mod_privileges.c` line 270

Privilege drop return value not checked. Failed setuid() leaves process running as root when it expects to be unprivileged.

```
if (cfg->gid && (setgid(cfg->gid) == -1)) {
```

**Fix:** Always check setuid() return: if (setuid(uid) != 0) { perror('setuid'); exit(1); }
---

### 44. [HIGH] Missing NULL check after allocation

**CWE-476** | `server/protocol.c` line 616

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
r->unparsed_uri = apr_pstrdup(r->pool, uri);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 45. [HIGH] Missing NULL check after allocation

**CWE-476** | `server/protocol.c` line 650

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
r->uri = apr_pstrdup(r->pool, "*");
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 46. [HIGH] Missing NULL check after allocation

**CWE-476** | `server/protocol.c` line 653

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
r->uri = apr_pstrdup(r->pool, "/");
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 47. [HIGH] Missing NULL check after allocation

**CWE-476** | `server/protocol.c` line 673

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
r->uri = apr_pstrdup(r->pool, uri);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 48. [HIGH] Missing NULL check after allocation

**CWE-476** | `server/protocol.c` line 1065

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
r = apr_pcalloc(p, sizeof(request_rec));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 49. [HIGH] Missing NULL check after allocation

**CWE-476** | `server/protocol.c` line 1365

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
method = apr_pstrdup(r->pool, breq->method);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 50. [HIGH] Missing NULL check after allocation

**CWE-476** | `server/protocol.c` line 1366

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
uri = apr_pstrdup(r->pool, breq->uri);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 51. [HIGH] Missing NULL check after allocation

**CWE-476** | `server/protocol.c` line 1367

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
protocol = apr_pstrdup(r->pool, breq->protocol);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 52. [HIGH] Missing NULL check after allocation

**CWE-476** | `server/protocol.c` line 2026

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
ctx = apr_pcalloc(r->pool, sizeof(*ctx));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 53. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/filters/mod_reflector.c` line 183

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
reflector_cfg *conf = apr_pcalloc(p, sizeof(reflector_cfg));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 54. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/http2/h2_ws.c` line 143

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
ws_ctx = apr_pcalloc(c2->pool, sizeof(*ws_ctx));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 55. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/metadata/mod_usertrack.c` line 168

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
apr_table_setn(r->notes, "cookie", apr_pstrdup(r->pool, cookiebuf));   /* log first time */
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 56. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/metadata/mod_usertrack.c` line 285

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
dcfg = (cookie_dir_rec *) apr_pcalloc(p, sizeof(cookie_dir_rec));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 57. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `modules/aaa/mod_authn_socache.c` line 274

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
strcpy(new_context, r->server->server_hostname);
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 58. [CRITICAL] Format string vulnerability

**CWE-134** | `modules/http2/h2_session.c` line 763

User-controlled string passed as printf format argument. Attacker reads stack memory or overwrites return addresses via %n.

```
apr_snprintf(sbuffer, sizeof(sbuffer),
```

**Fix:** Use a literal format string: printf("%s", user_input). Never pass user data as the format argument.
---

### 59. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/http2/h2_session.c` line 943

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
session = apr_pcalloc(pool, sizeof(h2_session));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 60. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/http2/h2_session.c` line 982

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
session->monitor = apr_pcalloc(pool, sizeof(h2_stream_monitor));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 61. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/http2/h2_session.c` line 1002

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
apr_pcalloc(session->pool, session->hd_scratch.max_len + 1);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 62. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/http2/h2_session.c` line 1004

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
apr_pcalloc(session->pool, session->hd_scratch.max_len + 1);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 63. [HIGH] Missing NULL check after allocation

**CWE-476** | `server/main.c` line 595

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
*new = apr_pstrdup(pcommands, opt_arg);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 64. [HIGH] Missing NULL check after allocation

**CWE-476** | `server/main.c` line 600

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
*new = apr_pstrdup(pcommands, opt_arg);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 65. [HIGH] Missing NULL check after allocation

**CWE-476** | `server/main.c` line 609

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
*new = apr_pstrdup(pcommands, opt_arg);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 66. [HIGH] Missing NULL check after allocation

**CWE-476** | `server/main.c` line 630

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
temp_error_log = apr_pstrdup(process->pool, opt_arg);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 67. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/aaa/mod_allowhandlers.c` line 83

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
ah_conf_t *conf = apr_pcalloc(p, sizeof(ah_conf_t));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 68. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/dav/main/util.c` line 40

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
dav_error *err = apr_pcalloc(p, sizeof(*err));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 69. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/dav/main/util.c` line 71

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
dav_error *err = apr_pcalloc(p, sizeof(*err));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 70. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/dav/main/util.c` line 465

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
dav_xmlns_info *xi = apr_pcalloc(pool, sizeof(*xi));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 71. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/dav/main/util.c` line 698

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
new_sl = apr_pcalloc(p, sizeof(*new_sl));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 72. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/dav/main/util.c` line 1743

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
ifhdr_new = apr_pcalloc(r->pool, sizeof(*ifhdr_new));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 73. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/dav/main/util.c` line 1748

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
ifhdr_new->state = apr_pcalloc(r->pool, sizeof(*ifhdr_new->state));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 74. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/dav/main/util.c` line 1828

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
new_response = apr_pcalloc(r->pool, sizeof(*new_response));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 75. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/dav/main/util.c` line 1882

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
propstat = apr_pcalloc(r->pool, sizeof(*propstat));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 76. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/dav/main/util.c` line 1891

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
new_response = apr_pcalloc(r->pool, sizeof(*new_response));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 77. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/dav/main/util.c` line 1936

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
lock_token = apr_pcalloc(r->pool, sizeof(dav_locktoken_list));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 78. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/dav/main/util.c` line 1968

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
char *s2 = apr_pstrdup(pool, s);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 79. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/cache/cache_util.c` line 160

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
newp = apr_pcalloc(r->pool, sizeof(cache_provider_list));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 80. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/cache/cache_util.c` line 322

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
cache->key = apr_pstrdup(r->pool, h->cache_obj->key);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 81. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/cache/cache_util.c` line 924

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
return apr_pstrdup(p, hashfile);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 82. [HIGH] Use-after-free pattern

**CWE-416** | `modules/http3/quic/detail/h3q_tls.c` line 102

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
SSL_CTX_free(ssl_ctx);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 83. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/http/mod_mime.c` line 271

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
char *key = apr_pstrdup(cmd->temp_pool, ext);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 84. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/http/mod_mime.c` line 272

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
char *value = apr_pstrdup(cmd->pool, value_);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 85. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/http/mod_mime.c` line 288

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
exinfo = apr_pcalloc(cmd->pool, sizeof(extension_info));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 86. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/http/mod_mime.c` line 289

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
key = apr_pstrdup(cmd->pool, key);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 87. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/http/mod_mime.c` line 323

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
suffix->name = apr_pstrdup(cmd->pool, ext);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 88. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/http/mod_mime.c` line 883

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
ext = apr_pstrdup(r->pool, fn);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 89. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/http/mod_mime.c` line 910

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
extcase = apr_pstrdup(r->pool, ext);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 90. [HIGH] Integer overflow in size calculation

**CWE-190** | `modules/ssl/ssl_engine_config.c` line 2572

Arithmetic in allocator argument can overflow to a small value, causing under-allocation and subsequent heap overflow.

```
s = dst = apr_pcalloc(p, strlen(s) + n + 1);
```

**Fix:** Validate sizes before arithmetic. Use calloc(n, size) for n*size. Check: if (n > SIZE_MAX / size) abort().
---

### 91. [HIGH] Use-after-free pattern

**CWE-416** | `modules/ssl/ssl_engine_config.c` line 106

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
SSL_CONF_CTX_free(ctx);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 92. [HIGH] Use-after-free pattern

**CWE-416** | `modules/ssl/ssl_engine_config.c` line 718

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
ENGINE_free(e);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 93. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/ssl/ssl_engine_config.c` line 57

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
mc = apr_pcalloc(pool, sizeof(*mc));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 94. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/ssl/ssl_engine_config.c` line 205

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
mctx->pks = apr_pcalloc(p, sizeof(*mctx->pks));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 95. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/ssl/ssl_engine_config.c` line 213

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
mctx->ticket_key = apr_pcalloc(p, sizeof(*mctx->ticket_key));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 96. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/ssl/ssl_engine_config.c` line 1640

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
ap_expr_info_t *info = apr_pcalloc(cmd->pool, sizeof(ap_expr_info_t));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 97. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/ssl/ssl_engine_config.c` line 2418

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
sc->server->srp_vfile = apr_pstrdup(cmd->pool, arg);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 98. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/ssl/ssl_engine_config.c` line 2427

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
sc->server->srp_unknown_user_seed = apr_pstrdup(cmd->pool, arg);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 99. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/ssl/ssl_engine_config.c` line 2572

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
s = dst = apr_pcalloc(p, strlen(s) + n + 1);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 100. [CRITICAL] Buffer overflow via unsafe string function

**CWE-120** | `modules/filters/mod_xml2enc.c` line 305

strcpy/strcat/sprintf/gets without bounds checking. Stack or heap overflow leads to code execution.

```
strcpy(str + match[1].rm_so + 5, r->content_type+match[1].rm_eo);
```

**Fix:** Use strncpy, strncat, snprintf with explicit size. Null-terminate manually. Prefer strlcpy/strlcat where available.
---

### 101. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/filters/mod_xml2enc.c` line 127

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
xml2ctx* ctx = apr_pcalloc(r->pool, sizeof(xml2ctx));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 102. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/filters/mod_xml2enc.c` line 317

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(xml2ctx));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 103. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/filters/mod_xml2enc.c` line 343

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
mtype = apr_pstrdup(f->r->pool, f->r->content_type);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 104. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/filters/mod_xml2enc.c` line 674

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
xml2cfg* ret = apr_pcalloc(pool, sizeof(xml2cfg));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 105. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/filters/mod_xml2enc.c` line 683

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
xml2cfg* ret = apr_pcalloc(pool, sizeof(xml2cfg));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 106. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/mappers/mod_userdir.c` line 106

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
userdir_config *newcfg = apr_pcalloc(p, sizeof(*newcfg));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 107. [HIGH] Missing NULL check after allocation

**CWE-476** | `modules/mappers/mod_userdir.c` line 118

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
userdir_config *cfg = apr_pcalloc(p, sizeof(userdir_config));
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---

### 108. [HIGH] Use-after-free pattern

**CWE-416** | `server/error_bucket.c` line 37

Freed pointer not immediately set to NULL. Dangling pointer reuse corrupts heap and can lead to code execution.

```
apr_bucket_free(h);
```

**Fix:** Set pointer to NULL immediately after free(). Enable AddressSanitizer in CI: -fsanitize=address.
---

### 109. [HIGH] Missing NULL check after allocation

**CWE-476** | `server/error_bucket.c` line 48

Return value of malloc/realloc not checked for NULL. On allocation failure the program dereferences NULL, causing a crash or exploitable condition.

```
h->data = apr_pstrdup(p, buf);
```

**Fix:** Always check: ptr = malloc(n); if (!ptr) { handle_error(); return; }
---
