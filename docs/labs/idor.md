# Lab: IDOR / BOLA (changing an ID)

**Goal:** read another customer's order by changing the number in the URL, then add the ownership check that blocks it.

**How to use it:** you are logged in as **priya**. Her orders are 1001 and 1006. Try other IDs, scan a range, then switch to **Fixed API** and repeat. Watch the SOC panel at the bottom change.

<div id="lab-idor" class="lab">Loading lab... (this page needs JavaScript)</div>

## What to notice

1. The vulnerable API checks "is the user logged in?" but never "does this order belong to this user?".
2. Scanning IDs 1000 to 1010 leaks every customer's name, address and phone number in one click.
3. The fixed API returns **403** for other people's orders. Those 403s are also what makes the abuse visible in the logs.

## The fix

```python
order = db.get_order(order_id)
if order is None:
    return 404
if order.owner_id != current_user.id:       # the ownership check
    return 403                              # or 404, so attackers cannot tell which IDs exist
return order.to_public_dict()               # return only the fields the screen needs
```

Long random IDs (UUIDs) make guessing harder, but they are only an extra layer. The ownership check is the real fix.

**Read more in the guide:** [API: BOLA](../part-2-api.md#2-broken-object-level-authorization-bola-also-called-idor) and [Web: Horizontal Privilege Escalation](../part-1-web.md#9-horizontal-privilege-escalation).
