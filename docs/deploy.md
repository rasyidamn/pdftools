# Panduan deploy PDF Merge Gateway

```
PC domain ──HTTPS──▶ IIS (Windows Auth, cek grup AD, URL Rewrite + ARR)
                       │  set X-Remote-User, X-Gateway-Secret, X-Forwarded-For
                       ▼
                 VM Linux :8000 (hanya dari IP IIS)
                   ├─ api       FastAPI      (satu-satunya port publik)
                   ├─ stirling  Stirling-PDF (jaringan internal saja)
                   └─ db        PostgreSQL   (jaringan internal saja, volume pgdata)
```

FastAPI tidak mengautentikasi. Ia hanya mempercayai `X-Remote-User` bila `X-Gateway-Secret` cocok. Jadi
**keamanan bergantung pada tiga hal**: secret tidak bocor, port 8000 hanya terbuka untuk IIS, dan IIS selalu
menimpa header dari klien.

---

## 1. VM Linux

```bash
git clone <repo> /opt/pdftool && cd /opt/pdftool
cp .env.example .env && chmod 600 .env
openssl rand -hex 24   # jalankan 3x: GATEWAY_SECRET, POSTGRES_PASSWORD, APP_DB_PASSWORD
nano .env              # isi API_BIND_IP (IP VM), secret, password, ADMIN_USERS
docker compose up -d --build
docker compose ps      # api dan db harus "healthy"
curl -s http://<API_BIND_IP>:8000/api/health   # {"status":"ok","db":true,"engine":true}
```

- `db/init/schema.sql.in` hanya dijalankan saat volume `pgdata` **masih kosong**. Untuk mengulang dari nol (data
  audit HILANG): `docker compose down && docker volume rm pdftool_pgdata`.
- Setelah Stirling diuji (bagian 6), sematkan versinya: `STIRLING_IMAGE=stirlingtools/stirling-pdf:<tag>`.
- Pembaruan aplikasi: `git pull && docker compose up -d --build`.

### Firewall: chain DOCKER-USER

Port yang dipublikasikan Docker **melewati ufw**. Batasi port api agar hanya bisa dihubungi dari server IIS:

```bash
IIS_IP=192.168.10.5
sudo iptables -I DOCKER-USER -p tcp -m conntrack --ctorigdstport 8000 --ctdir ORIGINAL \
     ! -s "$IIS_IP" -j DROP
sudo apt install iptables-persistent && sudo netfilter-persistent save
```

Uji dari PC lain: `curl http://<VM>:8000/api/health` harus **timeout**. Dari server IIS harus berhasil.

### TRUSTED_PROXY_IPS (opsional, lapisan tambahan)

Isi dengan IP yang **dilihat api** sebagai pengirim. Dengan userland-proxy Docker, IP itu bisa berupa gateway
bridge Docker (mis. `172.18.0.1`), bukan IP IIS. Cara memastikannya: biarkan kosong, kirim satu permintaan
dengan secret yang salah, lalu lihat `docker compose logs api | grep peer=`.

---

## 2. Server IIS

Fitur yang dibutuhkan: **Windows Authentication**, **URL Authorization**, **URL Rewrite**, **Application Request
Routing (ARR)**.

1. **ARR → Server Proxy Settings:** centang *Enable proxy*. Isi *Time-out* = 360 detik (lebih besar dari
   `ENGINE_TIMEOUT_S`). Isi *Preserve client IP in the following header* = `X-Forwarded-For`. ARR **menambahkan**
   IP klien di paling kanan, dan entri terkanan inilah yang dipakai api.
2. **Situs → Authentication:** *Anonymous* = **Disabled**, *Windows Authentication* = **Enabled**.
3. **URL Rewrite → View Server Variables:** tambahkan `HTTP_X_REMOTE_USER` dan `HTTP_X_GATEWAY_SECRET` ke daftar
   yang diizinkan.
4. `web.config` situs (ganti grup, IP VM, secret, dan batas ukuran):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <security>
      <authorization>
        <remove users="*" roles="" verbs="" />
        <add accessType="Allow" roles="AD-LAB\GG-PDFTool-Users" />
      </authorization>
      <requestFiltering>
        <!-- (MAX_TOTAL_MB + 5) MB. Ini yang membatasi upload chunked tanpa Content-Length. -->
        <requestLimits maxAllowedContentLength="110100480" />
      </requestFiltering>
    </security>
    <rewrite>
      <rules>
        <rule name="pdftool" stopProcessing="true">
          <match url="(.*)" />
          <serverVariables>
            <!-- SELALU ditimpa: nilai kiriman klien tidak pernah sampai ke api -->
            <set name="HTTP_X_REMOTE_USER" value="{LOGON_USER}" />
            <set name="HTTP_X_GATEWAY_SECRET" value="ISI_GATEWAY_SECRET" />
          </serverVariables>
          <action type="Rewrite" url="http://192.168.10.20:8000/{R:1}" />
        </rule>
      </rules>
    </rewrite>
  </system.webServer>
</configuration>
```

- `web.config` berisi secret. Batasi ACL foldernya (hanya Administrators dan identitas app pool), atau pindahkan
  bagian `serverVariables` ke `applicationHost.config`.
- `{LOGON_USER}` berbentuk `DOMAIN\user`. Bila kosong, api menjawab 401 `NO_USER`, dan biasanya penyebabnya
  Anonymous masih aktif.
- Pakai HTTPS di IIS (sertifikat CA internal). Koneksi IIS → VM berjalan di jaringan lokal lewat HTTP.

---

## 3. Simpan head_hash di tempat lain

Rantai hash mendeteksi baris yang diubah atau dihapus **di tengah**, tetapi tidak bisa mendeteksi penghapusan
baris **terakhir**. Karena itu admin wajib menyalin `head_hash` ke luar sistem secara berkala, minimal mingguan.

- **Manual:** halaman `/admin` → *Periksa rantai* → *Salin*. Tempel ke email atau tiket ke atasan, sehingga
  tersimpan bertanggal di sistem lain.
- **Otomatis (Task Scheduler di PC/server domain, akun admin):**

```powershell
$r = Invoke-RestMethod -Uri "https://pdftool.ad-lab.local/admin/verify" -UseDefaultCredentials
"$(Get-Date -Format s) ok=$($r.ok) rows=$($r.rows_checked) head=$($r.head_id) $($r.head_hash)" |
  Add-Content "\\fileserver\audit-pdftool\head_hash.log"
```

Saat diperiksa ulang, `head_id` dan `head_hash` lama harus tetap ada di rantai. Bila jumlah baris berkurang atau
hash lama hilang, berarti ada baris yang dihapus.

---

## 4. Backup

```bash
docker compose exec -T db pg_dump -U pdftool_owner -Fc pdftool > /backup/pdftool-$(date +%F).dump
```

Lakukan harian lewat cron dan salin ke luar VM. Restore dilakukan ke volume kosong dengan `pg_restore`.

## 5. Pemantauan

- `GET /api/health` (tanpa secret) mengembalikan 503 bila db atau Stirling bermasalah.
- `docker compose logs api | grep "AUDIT"` menampilkan kegagalan penulisan audit. Ini harus ditangani segera,
  karena merge akan ditolak (gagal-aman).

## 6. Daftar uji di VM (hapus baris di CLAUDE.md "Not yet verified" setelah lulus)

1. **Stirling asli:** gabungkan 3 PDF dengan **lebar halaman berbeda**, nama file sengaja terbalik (`c.pdf`,
   `a.pdf`, `b.pdf`). Hasil harus mengikuti urutan pilihan. Bila Stirling mengubah urutan, api menolak dengan
   `OUTPUT_ORDER` (lihat audit), jadi file yang salah tidak pernah sampai ke staf.
2. **Health Stirling:** `docker compose exec api python -c "import urllib.request as u;print(u.urlopen('http://stirling:8080/api/v1/info/status').status)"`
   harus mencetak 200.
3. **IIS:** dari PC domain, halaman `/` menampilkan nama `DOMAIN\user`. Dari PC lain, akses langsung ke
   `http://<VM>:8000/` harus timeout. Mengirim header `X-Remote-User` palsu lewat IIS tidak boleh mengubah nama
   yang tampil.
4. **Batas upload:** total di atas `MAX_TOTAL_MB` ditolak (413). Merge besar mendekati batas waktu tidak boleh
   terputus oleh timeout ARR.
5. **Audit:** di `/admin`, setiap uji di atas tercatat. *Periksa rantai* = utuh.
