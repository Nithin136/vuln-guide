/* Phase 3: in-browser vulnerability labs.
   Everything is SIMULATED in JavaScript: no real database, shell or network request is used.
   All DOM is built with createElement + textContent; user input is never interpreted as HTML,
   never passed to eval / Function, and never sent anywhere. */
(function () {
  "use strict";

  /* ---------- small helpers ---------- */
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }
  function pre(text, cls) { var p = el("pre", "lab-pre" + (cls ? " " + cls : "")); p.appendChild(el("code", null, text)); return p; }
  function btn(text, handler, cls) {
    var b = el("button", "lab-btn" + (cls ? " " + cls : ""), text);
    b.type = "button"; b.addEventListener("click", handler); return b;
  }
  function field(labelText, id, value) {
    var wrap = el("div", "lab-field"); var l = el("label", null, labelText); l.setAttribute("for", id);
    var i = el("input"); i.type = "text"; i.id = id; i.value = value || "";
    i.setAttribute("autocomplete", "off"); i.setAttribute("spellcheck", "false");
    wrap.appendChild(l); wrap.appendChild(i); return { wrap: wrap, input: i };
  }
  function section(title) {
    var box = el("div", "lab-card"); box.appendChild(el("div", "lab-title", title));
    return box;
  }
  function modeToggle(state, onChange, labelBad, labelGood) {
    var wrap = el("div", "lab-toggle");
    var a = el("button", "lab-seg active", labelBad), b = el("button", "lab-seg", labelGood);
    a.type = b.type = "button";
    function set(fixed) { state.fixed = fixed; a.classList.toggle("active", !fixed); b.classList.toggle("active", fixed); onChange(); }
    a.addEventListener("click", function () { set(false); });
    b.addEventListener("click", function () { set(true); });
    wrap.appendChild(a); wrap.appendChild(b); return wrap;
  }
  function parts(container, list) {            // list of [text, isUserInput]
    clear(container);
    list.forEach(function (x) { container.appendChild(el("span", x[1] ? "lab-user" : null, x[0])); });
  }
  function encodeHtml(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
  function pad(n) { return (n < 10 ? "0" : "") + n; }
  function apacheTime() {
    var d = new Date(), M = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
    return "[" + pad(d.getUTCDate()) + "/" + M[d.getUTCMonth()] + "/" + d.getUTCFullYear() + ":" + pad(d.getUTCHours()) + ":" + pad(d.getUTCMinutes()) + ":" + pad(d.getUTCSeconds()) + " +0000]";
  }
  function scan(rules, text) { return rules.filter(function (r) { return r.re.test(text); }).map(function (r) { return r.name; }); }
  function detectPanel(logLines, findings, idea, note) {
    var box = section("What a SOC analyst would see");
    box.appendChild(el("div", "lab-sub", "Simulated log line(s)"));
    box.appendChild(pre(logLines.join("\n")));
    if (findings.length) {
      box.appendChild(el("div", "lab-sub", "Suspicious patterns matched"));
      var ul = el("ul"); findings.forEach(function (f) { ul.appendChild(el("li", null, f)); }); box.appendChild(ul);
    } else {
      box.appendChild(el("div", "lab-note", "No suspicious pattern matched. This looks like normal use."));
    }
    box.appendChild(el("div", "lab-sub", "Example detection idea"));
    box.appendChild(pre(idea));
    box.appendChild(el("div", "lab-note", note || "Pattern matching is only a starting point: attackers can encode or split payloads to evade simple rules, so real detection also looks at response codes, request rates and context."));
    return box;
  }

  /* =====================================================================
     LAB 1: SQL injection (tiny SQL WHERE-clause engine, not real SQL)
     ===================================================================== */
  var USERS = [
    { id: 1, username: "admin", password: "S3cr3t!Admin", role: "admin" },
    { id: 2, username: "priya", password: "priya123", role: "user" },
    { id: 3, username: "ravi", password: "ravi@2024", role: "user" }
  ];
  var COLS = { id: 1, username: 1, password: 1, role: 1 };

  function tokenize(s) {
    var t = [], i = 0;
    while (i < s.length) {
      var c = s.charAt(i);
      if (/\s/.test(c)) { i++; continue; }
      if (c === "-" && s.charAt(i + 1) === "-") break;               // comment: ignore the rest
      if (c === "'") {
        var j = i + 1, str = "";
        for (;;) {
          if (j >= s.length) throw new Error("unterminated quoted string");
          if (s.charAt(j) === "'") { if (s.charAt(j + 1) === "'") { str += "'"; j += 2; continue; } break; }
          str += s.charAt(j); j++;
        }
        t.push({ k: "str", v: str }); i = j + 1; continue;
      }
      var rest = s.slice(i), m;
      if ((m = /^[0-9]+(\.[0-9]+)?/.exec(rest))) { t.push({ k: "num", v: parseFloat(m[0]) }); i += m[0].length; continue; }
      if ((m = /^[A-Za-z_][A-Za-z0-9_]*/.exec(rest))) {
        var u = m[0].toUpperCase();
        t.push(u === "AND" || u === "OR" || u === "NOT" ? { k: u } : { k: "id", v: m[0].toLowerCase() });
        i += m[0].length; continue;
      }
      var two = s.substr(i, 2);
      if (two === "<>" || two === "!=" || two === "<=" || two === ">=") { t.push({ k: "op", v: two === "!=" ? "<>" : two }); i += 2; continue; }
      if (c === "=" || c === "<" || c === ">") { t.push({ k: "op", v: c }); i++; continue; }
      if (c === "(" || c === ")" || c === ";") { t.push({ k: c }); i++; continue; }
      throw new Error("unexpected character '" + c + "'");
    }
    return t;
  }
  function tokText(t) { return t.k === "str" ? "'" + t.v + "'" : (t.v !== undefined ? String(t.v) : t.k); }
  function truthy(v) { if (typeof v === "boolean") return v; var n = parseFloat(v); return !isNaN(n) && n !== 0; }
  function compare(a, b, op) {
    var na = typeof a === "number" || (typeof a === "string" && a.trim() !== "" && !isNaN(Number(a)));
    var nb = typeof b === "number" || (typeof b === "string" && b.trim() !== "" && !isNaN(Number(b)));
    var x = a, y = b;
    if ((typeof a === "number" || typeof b === "number") && na && nb) { x = Number(a); y = Number(b); }
    else { x = String(a); y = String(b); }
    switch (op) {
      case "=": return x === y; case "<>": return x !== y;
      case "<": return x < y; case ">": return x > y; case "<=": return x <= y; default: return x >= y;
    }
  }
  function parseWhere(tokens) {
    var p = 0;
    function peek() { return tokens[p]; }
    function primary() {
      var t = peek();
      if (!t) throw new Error("syntax error: unexpected end of query");
      if (t.k === "str" || t.k === "num") { p++; return function () { return t.v; }; }
      if (t.k === "id") {
        if (!COLS[t.v]) throw new Error("unknown column '" + t.v + "'");
        p++; return function (row) { return row[t.v]; };
      }
      if (t.k === "(") {
        p++; var e = orE();
        if (!peek() || peek().k !== ")") throw new Error("syntax error: missing closing parenthesis");
        p++; return e;
      }
      throw new Error("syntax error near '" + tokText(t) + "'");
    }
    function cmp() {
      var l = primary();
      if (peek() && peek().k === "op") {
        var op = peek().v; p++; var r = primary();
        return function (row) { return compare(l(row), r(row), op); };
      }
      return l;
    }
    function notE() {
      if (peek() && peek().k === "NOT") { p++; var f = notE(); return function (row) { return !truthy(f(row)); }; }
      return cmp();
    }
    function andE() {
      var l = notE();
      while (peek() && peek().k === "AND") { p++; var r = notE(); l = (function (a, b) { return function (row) { return truthy(a(row)) && truthy(b(row)); }; })(l, r); }
      return l;
    }
    function orE() {
      var l = andE();
      while (peek() && peek().k === "OR") { p++; var r = andE(); l = (function (a, b) { return function (row) { return truthy(a(row)) || truthy(b(row)); }; })(l, r); }
      return l;
    }
    var expr = orE();
    if (p < tokens.length) {
      if (tokens[p].k === ";") throw new Error("stacked queries (';') are not supported in this demo, but real databases may allow them");
      throw new Error("syntax error near '" + tokText(tokens[p]) + "'");
    }
    return expr;
  }
  function sqlVulnerable(u, p) {
    var prefix = "SELECT * FROM users WHERE username='";
    var query = prefix + u + "' AND password='" + p + "'";
    var res = { query: query, rows: [], error: null };
    try { res.rows = USERS.filter(parseWhere(tokenize(query.slice(query.indexOf("WHERE ") + 6)))); }
    catch (e) { res.error = e.message; }
    return res;
  }
  function sqlFixed(u, p) {
    return { query: "SELECT * FROM users WHERE username = ? AND password = ?", params: [u, p],
             rows: USERS.filter(function (r) { return r.username === u && r.password === p; }), error: null };
  }
  var SQLI_RULES = [
    { name: "Boolean tautology (OR 1=1 or OR 'a'='a')", re: /\bor\b\s*['"]?\w+['"]?\s*=\s*['"]?\w+/i },
    { name: "SQL comment sequence (--)", re: /--/ },
    { name: "Quote followed by a SQL keyword", re: /'\s*(or|and|union|select|drop|insert|update|delete)\b/i },
    { name: "Single quote in a login field", re: /'/ }
  ];

  function initSqli(root) {
    var state = { fixed: false };
    var u = field("Username", "sq-u", "priya"), p = field("Password", "sq-p", "priya123");
    var out = el("div");
    function run() {
      var res = state.fixed ? sqlFixed(u.input.value, p.input.value) : sqlVulnerable(u.input.value, p.input.value);
      clear(out);
      var qb = section(state.fixed ? "Query sent to the database (fixed: parameterized)" : "Query sent to the database (vulnerable: string concatenation)");
      var q = pre("", "lab-query"); var code = q.firstChild;
      if (state.fixed) {
        code.textContent = res.query;
        qb.appendChild(q);
        qb.appendChild(el("div", "lab-sub", "Bound values (always treated as plain data, never as SQL)"));
        qb.appendChild(pre(JSON.stringify(res.params)));
      } else {
        parts(code, [["SELECT * FROM users WHERE username='", false], [u.input.value, true], ["' AND password='", false], [p.input.value, true], ["'", false]]);
        qb.appendChild(q);
        qb.appendChild(el("div", "lab-note", "Orange text is what you typed. In the vulnerable version it becomes part of the SQL command."));
      }
      out.appendChild(qb);
      var rb = section("Result");
      if (res.error) {
        rb.appendChild(el("div", "lab-banner warn", "Database error: " + res.error));
        rb.appendChild(el("div", "lab-note", "Errors like this tell an attacker the input reached the SQL parser. Real apps should show a generic error and log the details privately."));
      } else if (res.rows.length) {
        rb.appendChild(el("div", "lab-banner bad", "Logged in as " + res.rows[0].username + " (role: " + res.rows[0].role + ")"));
        rb.appendChild(el("div", "lab-note", "The query returned " + res.rows.length + " row(s): " + res.rows.map(function (r) { return r.username; }).join(", ") + "."));
        if (res.rows.length > 1 || (res.rows[0].username !== u.input.value && !state.fixed)) {
          rb.appendChild(el("div", "lab-note", "The app only checks 'did any row come back?', so this counts as a successful login, with no valid password."));
        }
      } else {
        rb.appendChild(el("div", "lab-banner ok", "Login failed: no matching user."));
      }
      out.appendChild(rb);
      var enc = function (s) { return encodeURIComponent(s); };
      var status = res.error ? 500 : (res.rows.length ? 200 : 401);
      out.appendChild(detectPanel(
        ["10.0.2.15 - - " + apacheTime() + " \"POST /login HTTP/1.1\" " + status + " \"username=" + enc(u.input.value) + "&password=" + enc(p.input.value) + "\""],
        scan(SQLI_RULES, u.input.value + " " + p.input.value),
        "alert when a login parameter matches:  (?i)(\\bor\\b\\s*['\"]?\\w+['\"]?\\s*=|--|'\\s*(or|union|select)\\b)\n+ also alert on HTTP 500 from /login, and on 200 responses for requests that matched the pattern.",
        "Real logs often do not store POST bodies. WAF logs, application logs or database error logs can show the same thing."));
    }
    var tools = el("div", "lab-card");
    tools.appendChild(el("div", "lab-title", "Fake login form"));
    tools.appendChild(modeToggle(state, run, "Vulnerable app", "Fixed app (parameterized)"));
    tools.appendChild(u.wrap); tools.appendChild(p.wrap);
    tools.appendChild(btn("Log in", run));
    tools.appendChild(el("div", "lab-sub", "Try these payloads"));
    var row = el("div", "lab-presets");
    [["Normal login", "priya", "priya123"], ["Wrong password", "priya", "guess"], ["Tautology in password", "admin", "' OR '1'='1"],
     ["Comment out the password", "admin' --", "anything"], ["OR 1=1 in username", "' OR 1=1 --", "x"], ["Lone quote (breaks the query)", "'", "x"],
     ["Stacked query", "x'; DROP TABLE users; --", "x"]].forEach(function (x) {
      row.appendChild(btn(x[0], function () { u.input.value = x[1]; p.input.value = x[2]; run(); }, "secondary"));
    });
    tools.appendChild(row);
    tools.appendChild(el("div", "lab-note", "Demo users: admin, priya, ravi. Passwords are kept in plain text here only to keep the demo simple; real apps must hash them."));
    root.appendChild(tools); root.appendChild(out); run();
  }

  /* =====================================================================
     LAB 2: XSS (simulated browser: input is analysed, never rendered as real HTML)
     ===================================================================== */
  function analyzeHtml(input) {
    var attacks = [], items = [], inScript = false, open = [];
    input.split(/(<[^>]*>?)/).forEach(function (tok) {
      if (!tok) return;
      var m = /^<\s*(\/?)\s*([a-zA-Z][a-zA-Z0-9]*)/.exec(tok);
      if (tok.charAt(0) !== "<" || !m) { if (!inScript) items.push({ type: "text", text: tok }); return; }
      var closing = m[1] === "/", name = m[2].toLowerCase();
      if (name === "script") {
        if (!closing) { attacks.push("<script> tag: the browser runs the JavaScript inside it"); inScript = true; } else { inScript = false; }
        return;
      }
      if (inScript) return;
      if (name === "b" || name === "i" || name === "u" || name === "strong" || name === "em") { items.push({ type: closing ? "close" : "open", name: name }); return; }
      if (closing) return;
      if (/\bon[a-z]+\s*=/i.test(tok)) { attacks.push("<" + name + "> with an event handler (onerror, onclick...): the handler runs"); items.push({ type: "text", text: "[" + name + " element]", muted: true }); return; }
      if (/javascript\s*:/i.test(tok)) { attacks.push("javascript: URL: runs when the link is clicked"); items.push({ type: "text", text: "[" + name + " element]", muted: true }); return; }
      items.push({ type: "text", text: "[" + name + " element]", muted: true });
    });
    return { items: items, attacks: attacks };
  }
  function renderItems(container, items) {
    clear(container);
    var stack = [container];
    items.forEach(function (it) {
      var top = stack[stack.length - 1];
      if (it.type === "text") { top.appendChild(el("span", it.muted ? "lab-muted" : null, it.text)); }
      else if (it.type === "open") { var n = el(it.name); top.appendChild(n); stack.push(n); }
      else if (stack.length > 1) { stack.pop(); }
    });
  }
  var XSS_RULES = [
    { name: "<script> tag", re: /<\s*script/i }, { name: "Inline event handler (onerror=, onload=...)", re: /\bon[a-z]+\s*=/i },
    { name: "javascript: URL", re: /javascript\s*:/i }, { name: "Tag that can load or run content (img, svg, iframe, body)", re: /<\s*(img|svg|iframe|body)\b/i }
  ];
  function initXss(root) {
    var inp = field("Search term or comment", "xs-in", "<b>hello</b>");
    var out = el("div", "lab-grid");
    function run() {
      var val = inp.input.value; clear(out);
      var a = analyzeHtml(val);
      var bad = section("Vulnerable page (inserts input as raw HTML)");
      var view = el("div", "lab-view"); view.appendChild(el("span", null, "Results for: ")); var slot = el("span"); renderItems(slot, a.items); view.appendChild(slot);
      bad.appendChild(view);
      if (a.attacks.length) {
        bad.appendChild(el("div", "lab-banner bad", "Attacker's script runs in the victim's browser"));
        var ul = el("ul"); a.attacks.forEach(function (x) { ul.appendChild(el("li", null, x)); }); bad.appendChild(ul);
        bad.appendChild(el("div", "lab-note", "Simulated effect: the script reads the victim's cookie (session=ABC123, fake) and sends it to https://evil.example/?c=session%3DABC123. Nothing is actually sent."));
      } else { bad.appendChild(el("div", "lab-banner ok", "No script ran. The page is only showing formatting.")); }
      bad.appendChild(el("div", "lab-sub", "HTML the server sent"));
      bad.appendChild(pre("<p>Results for: " + val + "</p>"));
      var good = section("Safe page (output is encoded)");
      var gv = el("div", "lab-view"); gv.appendChild(el("span", null, "Results for: ")); gv.appendChild(el("span", null, val)); good.appendChild(gv);
      good.appendChild(el("div", "lab-banner ok", "Shown as plain text. Nothing can run."));
      good.appendChild(el("div", "lab-sub", "HTML the server sent"));
      good.appendChild(pre("<p>Results for: " + encodeHtml(val) + "</p>"));
      out.appendChild(bad); out.appendChild(good);
      out.parentNode.querySelector(".lab-detect").replaceWith(buildDetect(val));
    }
    function buildDetect(val) {
      var d = detectPanel(["10.0.2.15 - - " + apacheTime() + " \"GET /search?q=" + encodeURIComponent(val) + " HTTP/1.1\" 200 1043"],
        scan(XSS_RULES, val),
        "alert when the query string or body matches:  (?i)(<\\s*script|\\bon[a-z]+\\s*=|javascript\\s*:)\n+ review the page's Content-Security-Policy report-only logs for blocked inline scripts.");
      d.classList.add("lab-detect"); return d;
    }
    var tools = el("div", "lab-card"); tools.appendChild(el("div", "lab-title", "Fake search page"));
    tools.appendChild(inp.wrap); tools.appendChild(btn("Search", run));
    tools.appendChild(el("div", "lab-sub", "Try these inputs"));
    var row = el("div", "lab-presets");
    [["Plain text", "red shoes"], ["Harmless formatting", "<b>hello</b>"], ["Script tag", "<script>steal(document.cookie)</script>"],
     ["Broken image + onerror", "<img src=x onerror=steal(document.cookie)>"], ["javascript: link", "<a href=\"javascript:steal()\">click me</a>"]].forEach(function (x) {
      row.appendChild(btn(x[0], function () { inp.input.value = x[1]; run(); }, "secondary"));
    });
    tools.appendChild(row);
    tools.appendChild(el("div", "lab-note", "This is a simulation. Your input is analysed as text and is never rendered as real HTML on this page."));
    root.appendChild(tools); root.appendChild(out);
    var placeholder = el("div", "lab-detect"); root.appendChild(placeholder); run();
  }

  /* =====================================================================
     LAB 3: IDOR / BOLA
     ===================================================================== */
  var ORDERS = {
    1001: { owner: "priya", name: "Priya Sharma", address: "14 Garden Street", phone: "+91 90000 00001", item: "Wireless mouse", total: 799 },
    1002: { owner: "ravi", name: "Ravi Kumar", address: "7 Lake View Road", phone: "+91 90000 00002", item: "Laptop stand", total: 1499 },
    1003: { owner: "sneha", name: "Sneha Reddy", address: "52 Hill Colony", phone: "+91 90000 00003", item: "Headphones", total: 2999 },
    1004: { owner: "arjun", name: "Arjun Rao", address: "3 Market Lane", phone: "+91 90000 00004", item: "USB-C cable", total: 399 },
    1005: { owner: "kiran", name: "Kiran Patel", address: "21 Station Road", phone: "+91 90000 00005", item: "Keyboard", total: 1999 },
    1006: { owner: "priya", name: "Priya Sharma", address: "14 Garden Street", phone: "+91 90000 00001", item: "Notebook set", total: 349 }
  };
  function orderApi(id, fixed, user) {
    var o = ORDERS[id];
    if (!o) return { status: 404, body: { error: "not found" } };
    if (fixed && o.owner !== user) return { status: 403, body: { error: "forbidden" } };
    return { status: 200, body: { id: id, name: o.name, address: o.address, phone: o.phone, item: o.item, total: o.total } };
  }
  function initIdor(root) {
    var state = { fixed: false }, USER = "priya", history = [];
    var idField = field("Order ID in the URL", "id-in", "1001");
    var out = el("div"), log = el("div");
    function record(id, r) { history.push({ id: id, status: r.status }); if (history.length > 30) history.shift(); }
    function renderLog() {
      clear(log);
      var lines = history.slice(-8).map(function (h) { return "10.0.2.15 - " + USER + " " + apacheTime() + " \"GET /api/orders/" + h.id + " HTTP/1.1\" " + h.status; });
      var ids = {}, n403 = 0, seq = false;
      history.forEach(function (h) { ids[h.id] = 1; if (h.status === 403) n403++; });
      var list = Object.keys(ids).map(Number).sort(function (a, b) { return a - b; });
      var run = 1, best = list.length ? 1 : 0;
      for (var i = 1; i < list.length; i++) { run = list[i] === list[i - 1] + 1 ? run + 1 : 1; if (run > best) best = run; }
      seq = best >= 5;
      var findings = [];
      if (seq) findings.push("One user requested " + best + " sequential order IDs: looks like ID enumeration");
      if (n403 >= 3) findings.push(n403 + " forbidden (403) responses from one user: repeated access to other people's records");
      log.appendChild(detectPanel(lines.length ? lines : ["(send a request to see log lines)"], findings,
        "alert when one user requests >= 10 distinct /api/orders/<id> values within 60 seconds,\nor gets >= 3 HTTP 403 responses from /api/orders/* within 60 seconds.",
        "In the vulnerable app there are no 403s, which makes the abuse harder to spot. Logging the object ID per user is what makes detection possible."));
    }
    function send(id) {
      var r = orderApi(id, state.fixed, USER); record(id, r); clear(out);
      var rb = section("Request and response");
      rb.appendChild(pre("GET /api/orders/" + id + " HTTP/1.1\nAuthorization: Bearer <priya's token>"));
      rb.appendChild(el("div", "lab-banner " + (r.status === 200 ? (ORDERS[id] && ORDERS[id].owner !== USER ? "bad" : "ok") : "warn"), "HTTP " + r.status));
      rb.appendChild(pre(JSON.stringify(r.body, null, 2)));
      if (r.status === 200 && ORDERS[id].owner !== USER) rb.appendChild(el("div", "lab-note", "Priya just read another customer's order. The API checked that she was logged in, but not that the order is hers."));
      if (r.status === 403) rb.appendChild(el("div", "lab-note", "The server compared the order's owner with the logged-in user and refused. Some APIs return 404 here instead, so attackers cannot tell which IDs exist."));
      out.appendChild(rb); renderLog();
    }
    function scanAll() {
      clear(out); var rb = section("Scan of IDs 1000 to 1010"); var leaked = 0, rows = [];
      for (var id = 1000; id <= 1010; id++) {
        var r = orderApi(id, state.fixed, USER); record(id, r);
        if (r.status === 200 && ORDERS[id].owner !== USER) leaked++;
        rows.push(id + "  ->  " + r.status + (r.status === 200 ? "  (" + (ORDERS[id].owner === USER ? "yours" : "someone else's: " + ORDERS[id].name) + ")" : ""));
      }
      rb.appendChild(pre(rows.join("\n")));
      rb.appendChild(el("div", "lab-banner " + (leaked ? "bad" : "ok"), leaked ? leaked + " other customers' records leaked" : "No other customers' records leaked"));
      out.appendChild(rb); renderLog();
    }
    var tools = section("Fake shop API");
    tools.appendChild(el("div", "lab-note", "You are logged in as priya. Her own orders are 1001 and 1006."));
    tools.appendChild(modeToggle(state, function () { send(Number(idField.input.value) || 0); }, "Vulnerable API (checks login only)", "Fixed API (checks ownership)"));
    tools.appendChild(idField.wrap);
    var row = el("div", "lab-presets");
    row.appendChild(btn("Send request", function () { send(Number(idField.input.value) || 0); }));
    row.appendChild(btn("Try next ID", function () { idField.input.value = String((Number(idField.input.value) || 1000) + 1); send(Number(idField.input.value)); }, "secondary"));
    row.appendChild(btn("Scan IDs 1000 to 1010", scanAll, "secondary"));
    row.appendChild(btn("Clear log", function () { history = []; renderLog(); }, "secondary"));
    tools.appendChild(row);
    root.appendChild(tools); root.appendChild(out); root.appendChild(log); send(1001);
  }

  /* =====================================================================
     LAB 4: Command injection (fake shell with canned output)
     ===================================================================== */
  function fakeCmd(cmd) {
    var a = cmd.trim().split(/\s+/); var name = a[0] || "";
    switch (name) {
      case "": return { out: "", code: 0 };
      case "ping": {
        var host = a[a.length - 1];
        if (a.length < 2 || !/^[A-Za-z0-9.\-]+$/.test(host) || host === "-c") return { out: "ping: usage error: destination address required", code: 2 };
        return { out: "PING " + host + ": 56 data bytes\n64 bytes from " + host + ": icmp_seq=0 ttl=117 time=12.4 ms\n--- " + host + " ping statistics ---\n1 packets transmitted, 1 packets received, 0.0% packet loss", code: 0 };
      }
      case "whoami": return { out: "www-data", code: 0 };
      case "id": return { out: "uid=33(www-data) gid=33(www-data) groups=33(www-data)", code: 0 };
      case "pwd": return { out: "/var/www/html", code: 0 };
      case "ls": return { out: "config.php  index.php  uploads", code: 0 };
      case "uname": return { out: "Linux webserver 5.15.0 x86_64 GNU/Linux", code: 0 };
      case "cat":
        if (a[1] === "/etc/passwd") return { out: "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin", code: 0 };
        if (a[1] === "config.php") return { out: "<?php\n$DB_USER = 'app';\n$DB_PASS = 'demo-password-not-real';", code: 0 };
        return { out: "cat: " + (a[1] || "") + ": No such file or directory", code: 1 };
      default: return { out: "sh: 1: " + name + ": not found", code: 127 };
    }
  }
  function splitShell(line) {                       // supports ; && || |
    var segs = [], cur = "", op = "", i = 0;
    while (i < line.length) {
      var two = line.substr(i, 2), c = line.charAt(i);
      if (two === "&&" || two === "||") { segs.push({ op: op, cmd: cur }); op = two; cur = ""; i += 2; }
      else if (c === ";" || c === "|" || c === "\n") { segs.push({ op: op, cmd: cur }); op = c === "\n" ? ";" : c; cur = ""; i++; }
      else { cur += c; i++; }
    }
    segs.push({ op: op, cmd: cur }); return segs;
  }
  function cmdVulnerable(host) {
    var line = "ping -c 1 " + host, outs = [], last = { code: 0 };
    splitShell(line).forEach(function (s) {
      var run = s.op === "" || s.op === ";" || s.op === "|" || (s.op === "&&" && last.code === 0) || (s.op === "||" && last.code !== 0);
      if (!run) return;
      var r = fakeCmd(s.cmd);
      if (s.op === "|") outs = [];                   // piped: only the last command's output is shown
      if (r.out) outs.push(r.out);
      last = r;
    });
    return { line: line, output: outs.join("\n"), argv: null, error: null };
  }
  function cmdFixed(host) {
    if (!/^[A-Za-z0-9]([A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?$/.test(host)) return { line: null, output: "", argv: null, error: "400 Bad Request: invalid host name" };
    return { line: null, output: fakeCmd("ping -c 1 " + host).out, argv: ["ping", "-c", "1", host], error: null };
  }
  var CMD_RULES = [
    { name: "Shell metacharacter in a host parameter (; & | ` $ ( ) < >)", re: /[;&|`$()<>\n]|%3b|%26|%7c|%60|%24/i },
    { name: "System command name in the input (cat, whoami, id, ls, uname, wget, curl, nc, bash)", re: /\b(cat|whoami|id|ls|uname|wget|curl|nc|bash|sh|chmod)\b/i },
    { name: "Access to sensitive files (/etc/passwd, config files)", re: /\/etc\/(passwd|shadow)|config\.php|\.env/i }
  ];
  function initCmd(root) {
    var state = { fixed: false }, host = field("Host to ping", "cm-in", "8.8.8.8"), out = el("div");
    function run() {
      var v = host.input.value, res = state.fixed ? cmdFixed(v) : cmdVulnerable(v); clear(out);
      var cb = section(state.fixed ? "How the fixed server runs it (no shell, argument list)" : "Command the vulnerable server builds");
      if (state.fixed) { cb.appendChild(pre(res.argv ? JSON.stringify(res.argv) : "(not executed)")); }
      else { var q = pre("", "lab-query"); parts(q.firstChild, [["ping -c 1 ", false], [v, true]]); cb.appendChild(q); cb.appendChild(el("div", "lab-note", "Orange text is what you typed. The shell treats ; && || | as separators between commands.")); }
      out.appendChild(cb);
      var rb = section("Server output (simulated)");
      if (res.error) { rb.appendChild(el("div", "lab-banner ok", res.error)); }
      else {
        rb.appendChild(pre(res.output || "(no output)"));
        var extra = /www-data|root:x|uid=|DB_PASS|Linux webserver|index\.php|\/var\/www\/html/.test(res.output);
        rb.appendChild(el("div", "lab-banner " + (extra ? "bad" : "ok"), extra ? "The attacker's extra command ran on the server" : "Only the intended ping ran"));
      }
      out.appendChild(rb);
      out.appendChild(detectPanel(["10.0.2.15 - - " + apacheTime() + " \"GET /tools/ping?host=" + encodeURIComponent(v) + " HTTP/1.1\" " + (res.error ? 400 : 200) + " 312"],
        scan(CMD_RULES, v),
        "alert when a parameter named host/ip/url matches:  [;&|`$()<>]\n+ on Linux servers, alert when the web server user (www-data) starts a shell or runs whoami, id, cat or curl (auditd / Sysmon for Linux / EDR process events).",
        "Process-creation logs are often better evidence than web logs: they show what actually ran."));
    }
    var tools = section("Fake network tool: ping checker");
    tools.appendChild(modeToggle(state, run, "Vulnerable server (builds a shell command)", "Fixed server (validates and avoids the shell)"));
    tools.appendChild(host.wrap); tools.appendChild(btn("Ping", run));
    tools.appendChild(el("div", "lab-sub", "Try these inputs"));
    var row = el("div", "lab-presets");
    [["Normal", "8.8.8.8"], ["; whoami", "8.8.8.8; whoami"], ["&& cat /etc/passwd", "8.8.8.8 && cat /etc/passwd"], ["|| id", "bad host || id"], ["| ls", "8.8.8.8 | ls"], ["; cat config.php", "8.8.8.8; cat config.php"]].forEach(function (x) {
      row.appendChild(btn(x[0], function () { host.input.value = x[1]; run(); }, "secondary"));
    });
    tools.appendChild(row);
    tools.appendChild(el("div", "lab-note", "This is a fake shell with canned output. No real command is ever run."));
    root.appendChild(tools); root.appendChild(out); run();
  }

  /* ---------- wire up (works with Material instant navigation) ---------- */
  var LABS = [["lab-sqli", initSqli], ["lab-xss", initXss], ["lab-idor", initIdor], ["lab-cmd", initCmd]];
  function initAll() {
    LABS.forEach(function (x) {
      var r = document.getElementById(x[0]);
      if (r && r.getAttribute("data-ready") !== "1") { r.setAttribute("data-ready", "1"); x[1](r); }
    });
  }
  window.VulnLabs = { sqlVulnerable: sqlVulnerable, sqlFixed: sqlFixed, analyzeHtml: analyzeHtml, orderApi: orderApi, cmdVulnerable: cmdVulnerable, cmdFixed: cmdFixed, scan: scan,
                      rules: { sqli: SQLI_RULES, xss: XSS_RULES, cmd: CMD_RULES } };
  if (typeof document$ !== "undefined" && document$.subscribe) { document$.subscribe(initAll); }
  else if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", initAll); }
  else { initAll(); }
})();
