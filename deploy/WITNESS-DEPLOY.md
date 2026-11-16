# Web Witness — Runbook deploy di VPS (sejajar gatekeeper)

Pola sama persis dengan `DEPLOY.md` gatekeeper: Caddy tetap satu-satunya pemilik
80/443, agent denger di loopback. **Port 8082** untuk Web Witness
(8080 = gatekeeper, 8081 = cadangan VFY).

## 0. Prasyarat

- VPS yang sama, Caddy + gatekeeper sudah jalan.
- Node 20+ (`node -v`).
- Subdomain baru di DuckDNS, contoh: `0xmurasaki-witness.duckdns.org`
  (tinggal tambah di dashboard DuckDNS, IP-nya sama).

## 1. Clone + build

```bash
cd /root
git clone https://github.com/LutfiAlfiansyah12/web-witness-agent.git web-witness
cd web-witness
npm ci --omit=dev || npm install
npm run build
npm test   # harus 50 passed, 0 failed
```

## 2. Config

```bash
cp .env.example .env
nano .env
```

Minimum untuk jalan (anchor ON, testnet):

```env
HOST=127.0.0.1
PORT=8082
ANCHOR_MODE=volta
ZKV_ANCHOR_SEED=<12 kata akun baru — JANGAN pakai akun utama lo>
ZKV_RPC_WSS=wss://zkverify-volta-rpc.zkverify.io
ZKV_EXPLORER=https://zkverify-testnet.subscan.io/
```

> Buat akun khusus (polkadot.js apps → account baru, simpan mnemonic di .env
> VPS saja). Faucet tVFY: https://www.faucy.com/zkverify-volta (atau via
> https://docs.zkverify.io/overview/getting-started/get_testnet_tokens) —
> 0.1 tVFY cukup untuk ratusan remark. Kalau belum mau kunci akun, set
> `ANCHOR_MODE=none` dulu — agent tetap jalan penuh (claim signed, anchor
> disabled), tinggal ganti env dan restart nanti.

## 3. Service

```bash
cp deploy/web-witness.service /etc/systemd/system/web-witness.service
systemctl daemon-reload
systemctl enable --now web-witness
journalctl -u web-witness -f
# health check:
curl -s http://127.0.0.1:8082/healthz
```

## 4. Caddy — tambah satu blok

Di `/etc/caddy/Caddyfile`, tambahkan (JANGAN ubah blok gatekeeper yang ada):

```caddyfile
0xmurasaki-witness.duckdns.org {
	reverse_proxy 127.0.0.1:8082
}
```

```bash
systemctl reload caddy
```

Cek dari luar:

```bash
curl -s https://0xmurasaki-witness.duckdns.org/healthz
curl -s https://0xmurasaki-witness.duckdns.org/publickey
```

## 5. Smoke test end-to-end

```bash
curl -sS -X POST https://0xmurasaki-witness.duckdns.org/witness \
  -H 'content-type: application/json' \
  -d '{"url":"https://api.github.com/repos/zkVerify/zkverifyjs","mode":"jsonpath","path":"stargazers_count"}'
# simpan "id" dari respons, lalu:
curl -sS "https://0xmurasaki-witness.duckdns.org/claims/<id>/verify?refetch=1"
```

Kalau anchor mode volta: tunggu ±10–30 detik, `anchor.status` berubah
`pending → submitted → finalized`, dan `explorer_url` menunjuk ke ekstrinsic
`system.remark` di Subscan. Isi remark harus persis
`webwitness/v1/<commitment>`.

## 6. Troubleshooting

| Gejala | Cek |
|---|---|
| `BLOCKED_TARGET` padahal URL publik | `FETCH_ALLOW_HOSTS/FETCH_DENY_HOSTS` di .env jangan sampai memblokir |
| anchor stuck `submitted` | `journalctl -u web-witness`; cek saldo akun anchor (faucet), cek RPC `wss://zkverify-volta-rpc.zkverify.io` |
| 429 terus | naikkan `RATE_LIMIT_MAX` di .env + `systemctl restart web-witness` |
| `EXTRACT_FAILED` | JSON path salah — coba manual `curl <url>` dan cocokkan struktur |
| Ga nemu domain | DuckDNS subdomain harus di-add dulu di dashboard DuckDNS |
| Port bentrok | `ss -tlnp | grep 8082`; jangan pakai 8080/8081 yang sudah dipakai |

## 7. Yang JANGAN dilakukan

- Jangan pernah commit `.env` atau isi `data/` (mnemonic + signing key).
- Jangan set `ALLOW_PRIVATE_TARGETS=true` di VPS.
- Jangan share seed akun anchor ke chat/logs.
