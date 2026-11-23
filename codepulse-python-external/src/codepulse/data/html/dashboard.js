(function () {
  "use strict";
  var data = JSON.parse(document.getElementById("cp-data").textContent);
  var SEV = ["critical", "high", "medium", "low", "info"];
  var OPEN = { open: 1, confirmed: 1, in_progress: 1 };
  function el(tag, attrs, kids) {
    var n = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "text") n.textContent = attrs[k]; else n.setAttribute(k, attrs[k]);
    });
    (kids || []).forEach(function (c) { if (c) n.appendChild(c); });
    return n;
  }
  function spark(runs) {
    var vals = runs.map(function (r) { return SEV.reduce(function (a, s) { return a + (r.by_severity[s] || 0); }, 0); });
    if (vals.length < 2) return el("span", { class: "muted", text: vals.length ? vals[0] + " findings" : "no runs" });
    var w = 160, h = 32, max = Math.max.apply(null, vals) || 1;
    var pts = vals.map(function (v, i) { return (i * w / (vals.length - 1)).toFixed(1) + "," + (h - 2 - v * (h - 4) / max).toFixed(1); }).join(" ");
    var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 " + w + " " + h); svg.setAttribute("class", "spark");
    svg.setAttribute("role", "img"); svg.setAttribute("aria-label", "findings per run: " + vals.join(", "));
    var pl = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
    pl.setAttribute("points", pts); svg.appendChild(pl);
    return svg;
  }
  function repoCard(r) {
    var bars = el("div", { class: "bars" }, SEV.map(function (s) {
      var n = r.open_by_severity[s] || 0;
      return el("span", { class: "chip", "data-sev": s, text: s + " " + n });
    }));
    var latest = r.latest_run ? (r.latest_run.created_at || "").slice(0, 16).replace("T", " ") + " · " + r.latest_run.mode : "never";
    return el("article", { class: "repo" }, [
      el("h3", { text: r.repository }),
      el("p", { class: "meta", text: r.open_total + " open · latest run " + latest + " · recurrences " + r.recurrences }),
      bars, spark(r.runs)
    ]);
  }
  var cards = document.getElementById("repos");
  data.repositories.forEach(function (r) { cards.appendChild(repoCard(r)); });
  if (!data.repositories.length) cards.appendChild(el("p", { class: "muted", text: "No stored runs yet. Run `codepulse review`." }));

  function opts(id, values) {
    var s = document.getElementById(id);
    values.forEach(function (v) { s.appendChild(el("option", { value: v, text: v })); });
  }
  function uniq(key) { var m = {}; data.issues.forEach(function (i) { m[i[key]] = 1; }); return Object.keys(m).sort(); }
  opts("f-repo", uniq("repository")); opts("f-sev", SEV); opts("f-status", uniq("status")); opts("f-rule", uniq("rule_id"));
  var body = document.getElementById("issues");
  var count = document.getElementById("count");
  function val(id) { return document.getElementById(id).value; }
  function render() {
    var q = val("f-text").toLowerCase(), onlyOpen = document.getElementById("f-open").checked, shown = 0;
    body.textContent = "";
    data.issues.forEach(function (i) {
      if (val("f-repo") && i.repository !== val("f-repo")) return;
      if (val("f-sev") && i.severity !== val("f-sev")) return;
      if (val("f-status") && i.status !== val("f-status")) return;
      if (val("f-rule") && i.rule_id !== val("f-rule")) return;
      if (onlyOpen && (!OPEN[i.status] || i.suppressed)) return;
      var hay = (i.path + " " + i.subcheck_id + " " + (i.message || "")).toLowerCase();
      if (q && hay.indexOf(q) < 0) return;
      shown++;
      var detail = el("tr", { class: "detail", hidden: "" }, [el("td", { colspan: "6" }, [
        el("p", { text: i.message || "" }),
        i.remediation ? el("p", { class: "fix", text: "Fix: " + i.remediation }) : null,
        el("p", { class: "meta", text: "fingerprint " + i.fingerprint + " · " + i.detection + " · " + (i.origin || "") }),
        el("button", { type: "button", class: "copy", text: "Copy as ticket (JSON)" })
      ])]);
      var row = el("tr", { class: "row", tabindex: "0", "data-sev": i.severity }, [
        el("td", {}, [el("span", { class: "chip", "data-sev": i.severity, text: i.severity })]),
        el("td", { text: i.status }), el("td", { text: i.repository }),
        el("td", {}, [el("code", { text: i.path + ":" + i.line })]),
        el("td", {}, [el("code", { text: i.subcheck_id })]),
        el("td", { text: (i.message || "").slice(0, 120) })
      ]);
      function toggle() { detail.hidden = !detail.hidden; }
      row.addEventListener("click", toggle);
      row.addEventListener("keydown", function (e) { if (e.key === "Enter") toggle(); });
      detail.querySelector(".copy").addEventListener("click", function (e) {
        var text = JSON.stringify(i.tracker, null, 2), b = e.target;
        (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject())
          .then(function () { b.textContent = "Copied"; }, function () { window.prompt("Ticket JSON", text); });
      });
      body.appendChild(row); body.appendChild(detail);
    });
    count.textContent = shown + " of " + data.issues.length + " issues";
  }
  ["f-repo", "f-sev", "f-status", "f-rule", "f-open"].forEach(function (id) { document.getElementById(id).addEventListener("change", render); });
  document.getElementById("f-text").addEventListener("input", render);
  render();
})();
