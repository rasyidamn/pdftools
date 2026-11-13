// Fungsi bersama halaman staf dan admin. Hanya textContent, tidak pernah HTML mentah.
"use strict";

const PDFTool = (() => {
  function $(id) {
    return document.getElementById(id);
  }

  function el(tag, text, cls) {
    const e = document.createElement(tag);
    if (text !== undefined && text !== null) e.textContent = String(text);
    if (cls) e.className = cls;
    return e;
  }

  function formatBytes(n) {
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
    return (n / (1024 * 1024)).toFixed(1) + " MB";
  }

  // Ubah respons error server menjadi pesan untuk staf (+ kode singkat untuk tim IT).
  async function errorMessage(resp) {
    let msg = "Terjadi kesalahan (HTTP " + resp.status + ").";
    let code = "";
    try {
      const body = await resp.json();
      if (body && body.detail && body.detail.message) msg = body.detail.message;
      if (body && body.detail && body.detail.code) code = body.detail.code;
    } catch (_) {
      if (resp.status === 413) msg = "Ukuran kiriman terlalu besar.";
      if (resp.status === 502 || resp.status === 504) msg = "Server sedang sibuk atau tidak merespons. Coba lagi nanti.";
    }
    const rid = (resp.headers.get("X-Request-ID") || "").slice(0, 8);
    const ref = [code, rid].filter(Boolean).join(" / ");
    return ref ? msg + " [" + ref + "]" : msg;
  }

  async function getJSON(url) {
    const resp = await fetch(url, { credentials: "same-origin", headers: { Accept: "application/json" } });
    if (!resp.ok) throw new Error(await errorMessage(resp));
    return resp.json();
  }

  function setStatus(node, text, kind) {
    node.textContent = text || "";
    node.className = "status" + (kind ? " " + kind : "");
  }

  return { $, el, formatBytes, errorMessage, getJSON, setStatus };
})();
