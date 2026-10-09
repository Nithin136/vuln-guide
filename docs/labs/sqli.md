# Lab: SQL injection login bypass

**Goal:** log in as `admin` without knowing the password, then see why the fixed version stops it.

**How to use it:** pick a payload button (or type your own), press **Log in**, and read the query. Then switch to **Fixed app** and try the same payload again.

<div id="lab-sqli" class="lab">Loading lab... (this page needs JavaScript)</div>

## What to notice

1. In the vulnerable app, your text is glued into the SQL command, so `' OR '1'='1` turns the password check into something that is always true.
2. `admin' --` works differently: the `--` comments out the rest of the query, including the password check.
3. A lone `'` causes a database error. Errors like that tell an attacker the input reached the SQL parser.
4. In the fixed app the same text is just a strange password that does not match.

## The fix

```python
# Vulnerable: input becomes part of the command
cursor.execute("SELECT * FROM users WHERE username='" + u + "' AND password='" + p + "'")

# Fixed: command and data are sent separately
cursor.execute("SELECT * FROM users WHERE username = %s", (u,))
user = cursor.fetchone()
if user and verify_password_hash(p, user.password_hash):   # compare against a bcrypt/Argon2 hash
    ...
```

Also give the database account the minimum rights, and show generic error messages.

**Read more in the guide:** [Web: SQL Injection](../part-1-web.md#18-sql-injection) and [API: SQL Injection](../part-2-api.md#12-sql-injection).

!!! note "About this simulator"

    It uses a tiny SQL engine written for this page that understands only simple `WHERE` conditions (`=`, `AND`, `OR`, `NOT`, parentheses and `--` comments). It is not a real database.
