// Halaman admin: lihat audit, ekspor CSV, periksa rantai hash.
"use strict";

(() => {
  const { $, el, formatBytes, getJSON, setStatus } = PDFTool;
  const LIMIT = 50;
  let offset = 0;
  let total = 0;

  const form = $("filters");
  const status = $("status");

  // Tanggal "sampai" di layar bersifat inklusif; server memakai batas eksklusif, jadi tambah 1 hari.
  function nextDay(iso) {
    const d = new Date(iso + "T00:00:00Z");
    d.setUTCDate(d.getUTCDate() + 1);
    return d.toISOString().slice(0, 10);
  }

  function params() {
    const p = new URLSearchParams();
    const data = new FormData(form);
    for (const [k, v] of data.entries()) {
      const s = String(v).trim();
      if (!s) continue;
      p.set(k, k === "until" ? nextDay(s) : s);
    }
    return p;
  }

  function updateCsvLink() {
    const q = params().toString();
    $("csv").href = "/admin/audit.csv" + (q ? "?" + q : "");
  }

  function filesCell(files) {
    const td = el("td");
    if (!files.length) {
      td.textContent = "-";
      return td;
    }
    const det = el("details");
    det.appendChild(el("summary", files.length + " file"));
    const ol = el("ol", null, "small");
    for (const f of files) {
      const li = el("li");
      li.appendChild(el("span", f.file_name));
      li.appendChild(
        el("span", " · " + formatBytes(f.size_bytes) + " · " + (f.pages ?? "?") + " hlm", "muted")
      );
      li.appendChild(el("code", f.sha256.slice(0, 16) + "…", "hash"));
      li.lastChild.title = f.sha256;
      ol.appendChild(li);
    }
    det.appendChild(ol);
    td.appendChild(det);
    return td;
  }

  function render(rows) {
    const body = $("rows");
    body.replaceChildren();
    if (!rows.length) {
      const tr = el("tr");
      const td = el("td", "Tidak ada data.", "muted");
      td.colSpan = 10;
      tr.appendChild(td);
      body.appendChild(tr);
    }
    for (const r of rows) {
      const tr = el("tr");
      tr.appendChild(el("td", r.id));
      tr.appendChild(el("td", (r.ts_utc || "").replace("T", " ").slice(0, 19)));
      tr.appendChild(el("td", r.username));
      tr.appendChild(el("td", r.client_ip));
      tr.appendChild(el("td", r.action));
      const st = el("td");
      st.appendChild(el("span", r.status, "badge " + String(r.status).toLowerCase()));
      tr.appendChild(st);
      const code = el("td", r.error_code || "");
      if (r.error_message || r.detail) code.title = r.error_message || r.detail;
      tr.appendChild(code);
      tr.appendChild(filesCell(r.files || []));
      tr.appendChild(el("td", r.output_pages ?? ""));
      tr.appendChild(el("td", (r.duration_ms / 1000).toFixed(1) + " dtk"));
      body.appendChild(tr);
    }
    const from = total ? offset + 1 : 0;
    $("page").textContent = from + "–" + Math.min(offset + LIMIT, total) + " dari " + total;
    $("prev").disabled = offset === 0;
    $("next").disabled = offset + LIMIT >= total;
  }

  async function load() {
    const p = params();
    p.set("limit", LIMIT);
    p.set("offset", offset);
    setStatus(status, "Memuat…", "busy");
    try {
      const data = await getJSON("/admin/audit?" + p.toString());
      total = data.total;
      render(data.rows);
      setStatus(status, "");
    } catch (e) {
      setStatus(status, e.message, "error");
    }
  }

  async function verify() {
    const btn = $("verify");
    btn.disabled = true;
    setStatus(status, "Memeriksa rantai audit…", "busy");
    try {
      const v = await getJSON("/admin/verify");
      $("verify-out").hidden = false;
      const sum = $("verify-summary");
      sum.textContent = v.ok
        ? "Rantai utuh. " + v.rows_checked + " baris diperiksa."
        : "RANTAI BERMASALAH: " + v.problem_count + " temuan pada " + v.rows_checked + " baris. Laporkan ke tim IT.";
      sum.className = v.ok ? "ok" : "error";
      $("head").textContent = v.head_hash ? "#" + v.head_id + " " + v.head_hash : "(kosong)";
      const ul = $("problems");
      ul.replaceChildren();
      for (const pr of v.problems) {
        ul.appendChild(el("li", "Baris " + pr.id + ": " + pr.type + (pr.fields ? " (" + pr.fields.join(", ") + ")" : "")));
      }
      setStatus(status, "");
    } catch (e) {
      setStatus(status, e.message, "error");
    } finally {
      btn.disabled = false;
    }
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    offset = 0;
    updateCsvLink();
    load();
  });
  form.addEventListener("input", updateCsvLink);
  $("prev").addEventListener("click", () => {
    offset = Math.max(0, offset - LIMIT);
    load();
  });
  $("next").addEventListener("click", () => {
    offset += LIMIT;
    load();
  });
  $("verify").addEventListener("click", verify);
  $("copy-head").addEventListener("click", () => {
    const t = $("head").textContent;
    if (navigator.clipboard) navigator.clipboard.writeText(t).catch(() => {});
  });

  updateCsvLink();
  load();
})();
