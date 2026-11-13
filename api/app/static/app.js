// Halaman staf: pilih file, atur urutan, gabungkan, unduh.
"use strict";

(() => {
  const { $, el, formatBytes, errorMessage, getJSON, setStatus } = PDFTool;

  let limits = { min_files: 2, max_files: 20, max_file_mb: 50, max_total_mb: 100, max_pages: 2000 };
  let files = [];
  let busy = false;

  const list = $("list");
  const status = $("status");
  const go = $("go");

  function isPdf(f) {
    return f.type === "application/pdf" || /\.pdf$/i.test(f.name);
  }

  function totalBytes() {
    return files.reduce((s, f) => s + f.size, 0);
  }

  // Cek sisi browser agar staf cepat tahu; server tetap memeriksa ulang.
  function problem() {
    if (files.length < limits.min_files) return "Pilih minimal " + limits.min_files + " file PDF.";
    if (files.length > limits.max_files) return "Maksimal " + limits.max_files + " file per proses.";
    const big = files.find((f) => f.size > limits.max_file_mb * 1024 * 1024);
    if (big) return big.name + ": ukuran melebihi " + limits.max_file_mb + " MB.";
    if (totalBytes() > limits.max_total_mb * 1024 * 1024) return "Total ukuran melebihi " + limits.max_total_mb + " MB.";
    return "";
  }

  // keepStatus=true: jangan timpa pesan hasil/error terakhir (dipakai setelah proses merge).
  function render(keepStatus) {
    list.replaceChildren();
    const tpl = $("file-row");
    files.forEach((f, i) => {
      const li = tpl.content.firstElementChild.cloneNode(true);
      li.querySelector(".pos").textContent = i + 1 + ".";
      li.querySelector(".name").textContent = f.name;
      li.querySelector(".size").textContent = formatBytes(f.size);
      const up = li.querySelector(".up");
      const down = li.querySelector(".down");
      up.disabled = busy || i === 0;
      down.disabled = busy || i === files.length - 1;
      li.querySelector(".remove").disabled = busy;
      up.addEventListener("click", () => move(i, -1));
      down.addEventListener("click", () => move(i, 1));
      li.querySelector(".remove").addEventListener("click", () => {
        files.splice(i, 1);
        render();
      });
      list.appendChild(li);
    });
    $("empty").hidden = files.length > 0;
    $("clear").hidden = files.length === 0 || busy;
    $("summary").textContent = files.length
      ? files.length + " file, total " + formatBytes(totalBytes())
      : "";
    const p = problem();
    go.disabled = busy || p !== "";
    if (!busy && !keepStatus && files.length > 0) setStatus(status, p, p ? "warn" : "");
  }

  function move(i, d) {
    const j = i + d;
    if (j < 0 || j >= files.length) return;
    [files[i], files[j]] = [files[j], files[i]];
    render();
  }

  function add(fileList) {
    const skipped = [];
    for (const f of fileList) {
      if (isPdf(f)) files.push(f);
      else skipped.push(f.name);
    }
    render();
    if (skipped.length) setStatus(status, "Bukan PDF, dilewati: " + skipped.join(", "), "warn");
  }

  function filenameFrom(resp) {
    const cd = resp.headers.get("Content-Disposition") || "";
    const m = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(cd);
    return m ? decodeURIComponent(m[1]) : "gabungan.pdf";
  }

  async function merge() {
    if (busy || problem()) return;
    busy = true;
    render(true);
    setStatus(status, "Sedang menggabungkan " + files.length + " file… mohon tunggu, jangan tutup halaman ini.", "busy");
    const form = new FormData();
    files.forEach((f) => form.append("files", f, f.name));
    try {
      const resp = await fetch("/api/merge", { method: "POST", body: form, credentials: "same-origin" });
      if (!resp.ok) {
        setStatus(status, await errorMessage(resp), "error");
        return;
      }
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = el("a");
      a.href = url;
      a.download = filenameFrom(resp);
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60000);
      setStatus(status, "Selesai. File " + a.download + " (" + formatBytes(blob.size) + ") sudah diunduh.", "ok");
    } catch (_) {
      setStatus(status, "Tidak bisa menghubungi server. Periksa jaringan lalu coba lagi.", "error");
    } finally {
      busy = false;
      render(true);
    }
  }

  // ---- event
  $("picker").addEventListener("change", (e) => {
    add(e.target.files);
    e.target.value = "";
  });
  const drop = $("drop");
  ["dragenter", "dragover"].forEach((t) =>
    drop.addEventListener(t, (e) => {
      e.preventDefault();
      drop.classList.add("over");
    })
  );
  ["dragleave", "drop"].forEach((t) => drop.addEventListener(t, () => drop.classList.remove("over")));
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    if (e.dataTransfer) add(e.dataTransfer.files);
  });
  $("clear").addEventListener("click", () => {
    files = [];
    setStatus(status, "");
    render();
  });
  go.addEventListener("click", merge);

  // ---- awal
  getJSON("/api/me")
    .then((me) => {
      limits = me.limits;
      $("who").textContent = me.username;
      $("admin-link").hidden = !me.is_admin;
      $("limits").textContent =
        "Minimal " + limits.min_files + ", maksimal " + limits.max_files + " file. Per file maks " +
        limits.max_file_mb + " MB, total maks " + limits.max_total_mb + " MB, maks " + limits.max_pages + " halaman.";
      render();
    })
    .catch((e) => setStatus(status, e.message, "error"));
  render();
})();
