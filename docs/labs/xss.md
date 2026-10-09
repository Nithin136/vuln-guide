# Lab: Cross-site scripting (XSS)

**Goal:** see what happens when a page puts user input into HTML as-is, compared with a page that encodes it.

**How to use it:** try each input. The left panel is the vulnerable page, the right panel is the safe one, and both show the exact HTML the server sent.

<div id="lab-xss" class="lab">Loading lab... (this page needs JavaScript)</div>

## What to notice

1. Harmless formatting like `<b>hello</b>` works on the vulnerable page. That is the problem: the browser cannot tell your formatting from an attacker's code.
2. A `<script>` tag, or an `onerror=` handler on an image, would run JavaScript in the victim's browser. In real attacks it can read cookies, change the page or act as the user.
3. On the safe page, `<` becomes `&lt;`, so the browser shows the text instead of running it.

## The fix

- **Encode output** for the place it lands (HTML body, attribute, JavaScript, URL). Frameworks do this for you until you use `innerHTML`, `v-html` or `dangerouslySetInnerHTML`.
- If you really need user HTML, **sanitize** it with a library such as DOMPurify.
- Add a **Content-Security-Policy** and set session cookies **`HttpOnly`** so scripts cannot read them.

**Read more in the guide:** [Reflected XSS](../part-1-web.md#14-reflected-xss), [Stored XSS](../part-1-web.md#19-stored-xss), [DOM XSS](../part-1-web.md#6-dom-xss-cross-site-scripting-browser-side) and [Front-end: Direct DOM Manipulation XSS](../part-8-frontend.md#2-direct-dom-manipulation-xss).

!!! note "About this simulator"

    Your input is analysed as text to decide what a browser would do. It is never rendered as real HTML here, so nothing on this page can actually run.
