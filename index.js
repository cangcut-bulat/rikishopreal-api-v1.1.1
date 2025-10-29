// --- REQ: Muat environment variables dari .env ---
// PENTING: Baris ini harus ada di PALING ATAS sebelum kode lain!
require('dotenv').config();
// --- Akhir REQ ---

const express = require('express');
const chalk = require('chalk');
const fs = require('fs');
const cors = require('cors');
const path = require('path');
const axios = require('axios'); // Dibutuhkan untuk Discord, IP Info & GitHub API
const { Ratelimit } = require('@upstash/ratelimit'); // Rate Limiter Baru (Untuk Vercel)
const { kv } = require('@vercel/kv'); // Vercel KV Client (Untuk Rate Limiter)

console.log("LOG: Script index.js (Vercel Mode) dimulai.");

// Import file function.js (opsional)
try {
  // Cek dulu apakah function.js ada sebelum require
  if (fs.existsSync(path.join(__dirname, 'function.js'))) {
    require("./function.js"); // Ini akan menambahkan fungsi ke global jika ada
    console.log("LOG: function.js dimuat (jika ada fungsi global, sudah ditambahkan).");
  } else {
    console.log("LOG: function.js tidak ditemukan, dilewati.");
  }
} catch (funcError) {
  console.warn(chalk.yellow("PERINGATAN: Gagal memproses function.js. Error: " + funcError.message));
}

const app = express();
// PORT di Vercel diatur otomatis, tapi ini bagus untuk lokal
const PORT = process.env.PORT || 8000;
console.log(`LOG: Port lokal (jika digunakan): ${PORT}`);

// Middleware Awal (Penting untuk proxy & parsing)
app.enable("trust proxy"); // WAJIB di Vercel untuk dapatkan IP asli
app.set("json spaces", 2); // Format output JSON (indentasi 2 spasi)
app.use(express.json()); // Parsing body JSON (untuk form laporan/admin)
app.use(express.urlencoded({ extended: false })); // Parsing body form-urlencoded standar
app.use(cors()); // Izinkan request lintas domain (Cross-Origin Resource Sharing)
console.log("LOG: Middleware dasar (proxy, parsing, cors) dimuat.");

// --- Middleware Otentikasi Admin ---
const checkAdminKey = (req, res, next) => {
  const adminKey = req.headers['x-admin-key']; // Ambil kunci dari header 'X-Admin-Key'
  const { ADMIN_API_KEY } = process.env; // Ambil kunci rahasia dari environment

  // Periksa apakah ADMIN_API_KEY sudah di-set di .env/Vercel Env Vars
  if (!ADMIN_API_KEY) {
    console.error(chalk.red("FATAL: ADMIN_API_KEY tidak diatur di environment variables!"));
    return res.status(500).json({ status: false, error: "Konfigurasi server admin error." });
  }

  // Periksa apakah header dikirim dan cocok
  if (!adminKey || adminKey !== ADMIN_API_KEY) {
    console.warn(chalk.yellow(`ADMIN: Upaya akses admin GAGAL dari IP: ${req.ip} ke ${req.path}`));
    return res.status(403).json({ status: false, error: "Akses ditolak. Kunci admin tidak valid atau tidak disertakan." });
  }

  // Jika kunci valid, lanjutkan
  next();
};
console.log(chalk.green("LOG: Middleware Admin (checkAdminKey) dimuat."));
// --- Akhir Middleware Otentikasi Admin ---


// --- Logika Blacklist IP (Adaptasi Vercel: Fetch per Request) ---
const BLACKLIST_URL = process.env.GITHUB_BLACKLIST_URL; // URL file JSON raw di GitHub

/**
 * Mengambil daftar IP blacklist dari GitHub dan MENGEMBALIKAN Set.
 * Tidak menyimpan state di global. Dijalankan per request yang perlu cek blacklist.
 * @returns {Promise<Set<string>>} Set berisi IP yang diblokir.
 */
async function fetchBlacklistAndReturnSet() {
  if (!BLACKLIST_URL) {
    console.warn(chalk.yellow("BLACKLIST: GITHUB_BLACKLIST_URL tidak diatur. Tidak ada IP yang diblokir."));
    return new Set(); // Kembalikan Set kosong jika URL tidak ada
  }
  // console.log(chalk.cyan("BLACKLIST: Fetching list from GitHub...")); // Terlalu berisik
  try {
    const response = await axios.get(BLACKLIST_URL, {
      timeout: 7000, // Timeout 7 detik (sesuaikan jika perlu)
      headers: { 'Cache-Control': 'no-cache', 'Pragma': 'no-cache', 'Expires': '0' } // Paksa ambil baru
    });
    if (Array.isArray(response.data)) {
      // Filter hanya string valid dan buat Set
      const blacklistSet = new Set(response.data.filter(ip => typeof ip === 'string' && ip.trim()));
      // console.log(chalk.green(`BLACKLIST: Fetched ${blacklistSet.size} IPs.`)); // Opsional
      return blacklistSet;
    } else {
      console.error(chalk.red("BLACKLIST: Format data dari URL salah. Mengembalikan Set kosong."), response.data);
      return new Set(); // Kembalikan Set kosong jika format salah
    }
  } catch (error) {
    console.error(chalk.red(`BLACKLIST: Gagal mengambil daftar IP: ${error.message}. Mengembalikan Set kosong.`));
    return new Set(); // Kembalikan Set kosong jika fetch gagal
  }
}

// Middleware Pemeriksa Blacklist (VERCEL VERSION - Async Fetch per Request)
// Dijalankan SETELAH auth admin, SEBELUM static files & rate limiter
app.use(async (req, res, next) => {
  // Path yang dilewati pemeriksaan blacklist
  const allowedPaths = ['/api/blacklist-info', '/api/my-ip', '/manage-blacklist'];
  if (req.path.startsWith('/admin/') || allowedPaths.includes(req.path)) {
    return next(); // Lewati pemeriksaan jika admin atau path info
  }

  // Ambil daftar blacklist terbaru SETIAP request (kecuali yang di-skip)
  const currentBlacklist = await fetchBlacklistAndReturnSet();
  const userIP = req.ip; // IP asli dari 'trust proxy'

  if (currentBlacklist.has(userIP)) {
    console.warn(chalk.bgRed.white.bold(` BLOKIR: Akses ditolak untuk IP ${userIP} (blacklist). Path: ${req.originalUrl || req.path} `));
    // Kirim respons HTML blokir
    res.status(403).send(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>403 Forbidden</title><style>body{background:#0a0a0a;color:#e0e0e0;font-family:'Courier New',Courier,monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:1rem;text-align:center}.container{max-width:600px;border:1px solid #ff4141;background:rgba(26,26,26,0.9);padding:2rem;border-radius:8px;box-shadow:0 0 30px rgba(255,65,65,0.3)}h1{color:#ff4141;margin-bottom:1rem;font-size:1.8rem}p{font-size:1rem;margin-bottom:1.5rem}pre{color:#ffab70;background:#1a1a1a;padding:0.5rem 1rem;border-radius:4px;display:inline-block;border:1px solid #333}</style></head><body><div class="container"><h1>[ ACCESS DENIED ]</h1><p>Akses dari alamat IP Anda telah diblokir secara permanen.</p><pre>IP Address: ${userIP}</pre></div></body></html>`);
    return; // Hentikan request
  }
  next(); // Lanjutkan jika IP tidak ada di blacklist
});
console.log(chalk.green("LOG: Middleware Pemeriksa Blacklist (Vercel Fetch-per-Request) dimuat."));
// --- Akhir Logika Blacklist IP ---


// Static file serving
// Di Vercel, ini mungkin tidak terlalu diperlukan jika Anda define 'public' di vercel.json, tapi tidak masalah ada
app.use('/', express.static(path.join(__dirname, '/')));
app.use('/', express.static(path.join(__dirname, 'api-page'))); // Folder frontend utama
app.use('/images', express.static(path.join(__dirname, 'images')));
app.use('/audio', express.static(path.join(__dirname, 'audio')));
console.log("LOG: Penyajian file statis dikonfigurasi.");

// Load settings.json (Ini aman karena bagian dari build)
const settingsPath = path.join(__dirname, './settings.json');
let settings = {};
// global.endpointStatus Dihapus dari sini
try {
  console.log("LOG: Mencoba membaca settings.json...");
  const settingsData = fs.readFileSync(settingsPath, 'utf-8');
  settings = JSON.parse(settingsData);
  global.settings = settings; // Settings masih bisa disimpan global karena dibaca saat init
  console.log("LOG: settings.json berhasil dibaca.");
  // Tidak ada lagi inisialisasi endpointStatus di sini
  // Tidak ada lagi setInterval fetchBlacklist
} catch (err) {
  // Tangani error jika file tidak ada, tidak bisa dibaca, atau JSON tidak valid
  console.error(chalk.red(`FATAL ERROR: Gagal memuat atau parse settings.json: ${err.message}`));
  console.error(chalk.red("Pastikan file settings.json ada di root folder, format JSON benar, dan server punya izin baca."));
  process.exit(1); // Hentikan server jika settings gagal dimuat
}

// Inisialisasi variabel global (Hanya API Key)
global.apikey = Array.isArray(settings.apikey) ? settings.apikey : [];
// global.totalreq Dihapus
console.log(`LOG: Variabel global (apikey: ${global.apikey.length} keys) diinisialisasi.`);

// --- Pusat Kontrol Notifikasi Discord (TERMASUK blacklist_action) ---
const WEBHOOK_URLS = {
  report: process.env.DISCORD_WEBHOOK_REPORT,
  feature: process.env.DISCORD_WEBHOOK_FEATURE,
  ddos: process.env.DISCORD_WEBHOOK_DDOS,
  error: process.env.DISCORD_WEBHOOK_ERROR,
  activity: process.env.DISCORD_WEBHOOK_ACTIVITY,
  blacklist_action: process.env.DISCORD_WEBHOOK_BLACKLIST // Webhook untuk log blacklist
};
// Validasi URL Webhook
let webhooksConfiguredCount = 0;
console.log("LOG: Memvalidasi URL Discord Webhook...");
for (const key in WEBHOOK_URLS) {
  if (WEBHOOK_URLS[key] && WEBHOOK_URLS[key].startsWith('https://discord.com/api/webhooks/')) {
     webhooksConfiguredCount++;
  } else {
     // Beri peringatan jika webhook penting kosong/tidak valid
     if (key !== 'activity' && key !== 'blacklist_action' && !WEBHOOK_URLS[key]) { // Anggap report, feature, ddos, error penting
         console.warn(chalk.yellow(`  - PERINGATAN: Env var DISCORD_WEBHOOK_${key.toUpperCase()} kosong/tidak valid. Notifikasi '${key}' diabaikan.`));
     } else if (!WEBHOOK_URLS[key]) {
         console.log(chalk.gray(`  - INFO: DISCORD_WEBHOOK_${key.toUpperCase()} tidak diatur. Log '${key}' Discord dilewati.`));
     }
  }
}
if (webhooksConfiguredCount > 0) console.log(chalk.green(`LOG: ${webhooksConfiguredCount} URL Discord Webhook valid dimuat.`));
else console.warn(chalk.yellow("LOG: Tidak ada URL Discord Webhook yang valid dikonfigurasi."));

/**
 * Fungsi Pengirim Notifikasi Discord Universal
 * @param {('report'|'feature'|'ddos'|'error'|'activity'|'blacklist_action')} type Tipe notifikasi
 * @param {object} data Objek data payload
 */
async function sendDiscordAlert(type, data) {
  const url = WEBHOOK_URLS[type];
  if (!url) return; // URL tidak valid atau tidak diset, abaikan

  let embedPayload = {
    username: "API Bot Notification", // Nama default lebih generik
    avatar_url: "https://i.imgur.com/R3vQvjV.png", // Default icon
    embeds: [{
      timestamp: new Date().toISOString(),
      footer: { text: `API Service | ${global.settings?.creator || 'Rikishopreal'}` }
    }]
  };
  let embed = embedPayload.embeds[0];

  try { // Tangani error pembuatan embed
      switch (type) {
        case 'ddos':
          embedPayload.username = "Bot DDoS Alert";
          embedPayload.avatar_url = "https://i.imgur.com/o3N30iI.png"; // Icon alert
          embedPayload.content = "@here ⚠️ **RATE LIMIT TERPICU!** ⚠️"; // Mention @here
          embed.title = "🚨 Security Alert: Abnormal Activity Detected";
          embed.color = 15158332; // Merah terang
          embed.description = `IP terdeteksi melakukan request berlebihan dan telah **diblokir sementara** oleh rate limiter.\nPertimbangkan untuk memblokir IP ini secara permanen jika aktivitas berlanjut/mencurigakan.`;
          embed.fields = [
            { name: "IP Address", value: `\`${data.ip || 'N/A'}\``, inline: true },
            { name: "Endpoint Hit", value: `\`${data.endpoint || '/'}\``, inline: true },
            { name: "ISP", value: data.ipInfo?.isp || 'N/A', inline: false },
            { name: "Location", value: `${data.ipInfo?.city || 'N/A'}, ${data.ipInfo?.country || 'N/A'}`, inline: true },
            { name: "Organization", value: data.ipInfo?.org || 'N/A', inline: true }
          ];
          break;

        case 'report':
          embedPayload.username = "Bot Laporan Error";
          embedPayload.avatar_url = "https://i.imgur.com/fJ3wY1R.png"; // Icon bug
          embed.title = "🐞 Laporan Error Baru Diterima";
          embed.color = 16736336; // Oranye
          embed.description = data.teks || 'Tidak ada deskripsi laporan.';
          embed.fields = [
            { name: "Pelapor", value: `\`${data.nama || 'Anonim'}\``, inline: true },
            { name: "IP Pelapor", value: `\`${data.ip || 'N/A'}\``, inline: true }
          ];
          break;

        case 'feature':
          embedPayload.username = "Bot Request Fitur";
          embedPayload.avatar_url = "https://i.imgur.com/mJ3V1pQ.png"; // Icon ide/bintang
          embed.title = "✨ Request Fitur Baru Diajukan";
          embed.color = 3447003; // Biru muda
          embed.description = data.teks || 'Tidak ada deskripsi request.';
          embed.fields = [
            { name: "Pengaju", value: `\`${data.nama || 'Anonim'}\``, inline: true },
            { name: "IP Pengaju", value: `\`${data.ip || 'N/A'}\``, inline: true }
          ];
          break;

        case 'error': // Log error 500 dari error handler
          embedPayload.username = "Bot Error Log";
          embedPayload.avatar_url = "https://i.imgur.com/N6dZBC1.png"; // Icon error/ledakan
          embed.title = "💥 Internal Server Error (500)";
          embed.color = 13632027; // Kuning tua/Merah bata
          embed.description = `Server mengalami kesalahan internal saat memproses request. Periksa log server untuk detail.`;
          embed.fields = [
            { name: "IP Client", value: `\`${data.ip || 'N/A'}\``, inline: true },
            { name: "Endpoint", value: `\`${data.endpoint || '/'}\``, inline: true },
            { name: "Error Message", value: `\`\`\`\n${(data.errorMessage || 'Unknown Server Error').substring(0, 1000)}\n\`\`\``, inline: false }
          ];
          break;

        case 'activity':
          if (!WEBHOOK_URLS.activity) return; // Abaikan jika webhook activity tidak diset
          embedPayload.username = "API Activity Logger";
          embedPayload.avatar_url = "https://i.imgur.com/JCh6sEK.png"; // Icon log/history
          embed.title = `▶️ ${data.method} ${data.endpoint}`;
          embed.color = data.statusCode >= 500 ? 15158332 : (data.statusCode >= 400 ? 16736336 : 4886754);
          embed.fields = [
              { name: "IP Address", value: `\`${data.ip || 'N/A'}\``, inline: true },
              { name: "Status Code", value: `\`${data.statusCode}\``, inline: true },
              ...(data.duration !== undefined && data.duration >= 0 ? [{ name: "Duration", value: `\`${data.duration} ms\``, inline: true }] : []),
              { name: "API Key Used?", value: data.apiKeyUsed ? '✅ Yes' : '❌ No', inline: true },
              { name: "User Agent", value: `\`\`\`${(data.userAgent || 'N/A').substring(0, 500)}${(data.userAgent || '').length > 500 ? '...' : ''}\`\`\``, inline: false }
          ];
          delete embed.footer;
          break;

        case 'blacklist_action':
          embedPayload.username = "Bot Blacklist Log";
          embedPayload.avatar_url = "https://i.imgur.com/gKM1gW4.png"; // Icon gembok/log
          const actionText = data.action === 'blacklisted' ? 'Ditambahkan ke Blacklist' : 'Dihapus dari Blacklist';
          const color = data.action === 'blacklisted' ? 15158332 : 3066993; // Merah : Hijau
          embed.title = `🔒 IP ${actionText}`;
          embed.color = color;
          embed.description = `Alamat IP \`${data.ip || 'N/A'}\` telah **${actionText}**.`;
          embed.fields = [
              { name: "Aksi Dilakukan Oleh Admin (IP)", value: `\`${data.adminIp || 'N/A'}\``, inline: true },
              { name: "Timestamp Aksi", value: `<t:${Math.floor(Date.now() / 1000)}:R>`, inline: true }
          ];
          break;

        default:
           console.warn(chalk.yellow(`DISCORD: Tipe notifikasi tidak dikenal saat membuat embed: ${type}`));
           return;
      }
  } catch (embedError) {
      console.error(chalk.red(`DISCORD: Gagal membuat embed untuk tipe '${type}': ${embedError.message}`), embedError);
      return;
  }

  // Kirim embed ke Discord
  try {
    await axios.post(url, embedPayload, { headers: { 'Content-Type': 'application/json' }, timeout: 8000 });
    if (type !== 'activity') { console.log(chalk.green(`DISCORD: Notifikasi tipe '${type}' berhasil terkirim.`)); }
  } catch (error) {
    console.error(chalk.red(`DISCORD: Gagal mengirim notifikasi '${type}'. Error: ${error.message}`));
    if (error.response) { console.error(chalk.red(`  -> Status Discord: ${error.response.status}`)); if(error.response.status >= 400 && error.response.status < 500) { console.error(chalk.red(`  -> Data Discord: ${JSON.stringify(error.response.data)}`)); } }
    else if (error.request) { console.error(chalk.red('  -> Error: Tidak ada respons dari Discord (timeout atau masalah jaringan?).')); }
    else { console.error(chalk.red('  -> Error saat setup request Axios:', error.message)); }
  }
}
// --- Akhir Pusat Kontrol Notifikasi Discord ---


// --- Middleware Pencatatan Request & Format JSON ---
app.use((req, res, next) => {
  const start = Date.now();
  const isStaticAsset = /\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|map|mp3|json|txt|html)$/i.test(req.path) || req.path === '/favicon.ico';
  const logThisRequest = !(isStaticAsset && req.method === 'GET' && Object.keys(req.query).length === 0);

  if (logThisRequest) { console.log(chalk.bgHex('#E0E0E0').hex('#333').bold(` > ${req.method} ${req.originalUrl || req.path} `) + chalk.gray(`(IP: ${req.ip})`)); }
  // global.totalreq Dihapus

  // Modifikasi res.json
  const originalJson = res.json;
  res.json = function (data) {
    if (data && typeof data === 'object' && !data.error && res.statusCode >= 200 && res.statusCode < 300) {
      const responseData = data.creator ? data : { creator: global.settings.creator || "Rikishopreal", ...data };
      return originalJson.call(this, responseData);
    }
    return originalJson.call(this, data);
  };

  // Kirim Log Aktivitas ke Discord
  res.on('finish', () => {
      if (logThisRequest && res.statusCode !== 404 && res.statusCode !== 429) {
           const duration = Date.now() - start;
           sendDiscordAlert('activity', { ip: req.ip, method: req.method, endpoint: req.originalUrl || req.path, statusCode: res.statusCode, userAgent: req.headers['user-agent'], apiKeyUsed: !!(req.query.apikey || req.headers['x-api-key']), duration: duration });
           const durationText = `${duration}ms`; const durationColor = duration > 4000 ? chalk.red : (duration > 1000 ? chalk.yellow : chalk.green); // Sesuaikan threshold Vercel
           const statusText = `${res.statusCode}`; const statusColor = res.statusCode >= 500 ? chalk.bgRed.white.bold : (res.statusCode >= 400 ? chalk.bgYellow.black.bold : chalk.bgGreen.black.bold);
           console.log(chalk.gray(` < Respon ${statusColor(` ${statusText} `)} dalam ${durationColor(durationText)}`));
      }
  });
  next();
});
console.log("LOG: Middleware response JSON & Activity Log dimuat.");
// --- Akhir Middleware Log Request ---


// --- Logika Keamanan (Rate Limiter Vercel KV) ---
async function getIpInfo(ip) {
    let cleanIp = ip;
    const isPrivate = /^(::f{4}:)?(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|localhost|::1)/.test(ip);
    if (!ip || isPrivate) { return { isp: 'Local/Internal', country: 'N/A', city: 'N/A', org: 'N/A' }; }
    if (ip.startsWith('::ffff:')) { cleanIp = ip.split(':').pop(); }
    try {
        let url = `https://ip-api.com/json/${cleanIp}?fields=status,message,country,city,isp,org`;
        const response = await axios.get(url, { timeout: 3500 });
        if (response.data.status === 'success' || response.data.country) {
            return { isp: response.data.isp || response.data.org || 'N/A', country: response.data.country || 'N/A', city: response.data.city || 'N/A', org: response.data.org || response.data.isp || 'N/A' };
        } else { console.warn(chalk.yellow(`IP LOOKUP: Gagal untuk ${cleanIp}: ${response.data.message || 'Status bukan success'}`)); return { isp: `Lookup Failed`, country: 'N/A', city: 'N/A', org: 'N/A' }; }
    } catch (error) { let errorType = 'Lookup Error'; if (axios.isCancel(error) || error.code === 'ECONNABORTED' || error.message.includes('timeout')) { errorType = 'Lookup Timeout'; } console.error(chalk.red(`IP LOOKUP: Gagal request untuk ${cleanIp}: (${errorType}) ${error.message}`)); return { isp: errorType, country: 'N/A', city: 'N/A', org: 'N/A' }; }
}

const limitHandler = async (req, res /*, options */) => {
    const ip = req.ip;
    console.warn(chalk.bgMagenta.white.bold(` RATE LIMIT: IP ${ip} diblokir sementara. Endpoint: ${req.originalUrl || req.path} `));
    const ipInfo = await getIpInfo(ip);
    sendDiscordAlert('ddos', { ip: ip, endpoint: req.originalUrl || req.path, ipInfo: ipInfo });
    res.status(429).send(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>429 Too Many Requests</title><style>@import url('https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap');body{background:#0a0a0a;color:#e0e0e0;font-family:'Roboto Mono','Courier New',Courier,monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:1rem;text-align:center;}.container{max-width:700px;width:100%;border:1px solid #ffab70;background:rgba(26,26,26,0.9);padding:1.5rem 2rem;border-radius:8px;box-shadow:0 0 30px rgba(255,171,112,0.3);animation:fadeIn .5s ease;}@keyframes fadeIn{from{opacity:0;transform:translateY(10px);}to{opacity:1;transform:translateY(0);}}h1{color:#ffab70;font-size:1.5rem;text-transform:uppercase;letter-spacing:2px;margin-top:0;margin-bottom:1.5rem;}pre{background:#0a0a0a;border:1px solid #444;padding:1rem;border-radius:4px;white-space:pre-wrap;word-wrap:break-word;font-size:.9rem;line-height:1.6;text-align:left;margin-bottom:1.5rem;}.key{color:#88d7ff;font-weight:700;}.value{color:#ffab70;}.comment{color:#505050;display:block;margin-top:.5em;}.info{margin-top:1.5rem;font-size:.8rem;color:#888;}</style></head><body><div class="container"><h1>[ Rate Limit Exceeded ]</h1><pre><span class="key">STATUS</span>   : <span class="value">ACCESS TEMPORARILY BLOCKED (Code: 429)</span>\n<span class="key">REASON</span>   : <span class="value">Too Many Requests.</span>\n<span class="comment">// Anda mengirim terlalu banyak request dalam waktu singkat.</span>\n\n<span class="key">YOUR_IP</span>  : <span class="value">${ip||'Unavailable'}</span>\n<span class="key">DETAILS</span>  :\n  <span class="key">Country</span>  : <span class="value">${ipInfo?.country||'N/A'}</span>\n  <span class="key">City</span>     : <span class="value">${ipInfo?.city||'N/A'}</span>\n  <span class="key">ISP</span>      : <span class="value">${ipInfo?.isp||'N/A'}</span>\n\n<span class="comment">// Aktivitas Anda telah dicatat. Silakan coba lagi setelah beberapa saat.</span></pre><p class="info">Jika Anda merasa ini adalah kesalahan, hubungi administrator.</p></div></body></html>`);
};

// Inisialisasi Rate Limiter dengan Vercel KV
const ratelimit = kv
  ? new Ratelimit({
      redis: kv,
      limiter: Ratelimit.slidingWindow(
          parseInt(process.env.RATE_LIMIT_PER_MINUTE || "30"), "60 s"
      ),
      analytics: true,
      prefix: process.env.RATELIMIT_KV_PREFIX || "ratelimit_api",
      ephemeralCache: new Map(),
    })
  : null;

if (!ratelimit) { console.warn(chalk.yellow("PERINGATAN: Vercel KV tidak terkonfigurasi. Rate limiting dilewati!")); }

// Middleware Rate Limiter Baru
app.use(async (req, res, next) => {
    if (!ratelimit) return next(); // Lewati jika tidak aktif
    const path = req.path;
    const skippedPaths = [ '/', '/api/endpoint-status', '/api/submit-report', '/api/blacklist-info', '/api/my-ip', '/manage-blacklist' ];
    const isStaticAsset = /\.(html|css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|map|mp3|json|txt)$/i.test(path) || path === '/favicon.ico';
    const isAdminApi = path.startsWith('/admin/'); // API Admin tetap di-rate limit

    if (skippedPaths.includes(path) || isStaticAsset) { return next(); }

    const ip = req.ip ?? "127.0.0.1";
    try {
        const { success, limit, remaining, reset } = await ratelimit.limit(`ip:${ip}`);
        res.setHeader('RateLimit-Limit', limit.toString());
        res.setHeader('RateLimit-Remaining', remaining.toString());
        res.setHeader('RateLimit-Reset', Math.floor(reset / 1000).toString());

        if (!success) {
            const delta = Math.max(0, Math.ceil((reset - Date.now()) / 1000));
            res.setHeader('Retry-After', delta.toString());
            await limitHandler(req, res);
            // Tidak perlu next() karena response sudah dikirim
        } else {
            next();
        }
    } catch (error) { console.error(chalk.red("RATE LIMITER ERROR:"), error); next(); } // Loloskan jika error
});
if (ratelimit) { console.log(chalk.bgHex('#FFD700').hex('#333').bold(`LOG: Middleware Keamanan (Rate Limiter Vercel KV: ${process.env.RATE_LIMIT_PER_MINUTE || 30}/menit) dimuat.`)); }
// --- Akhir Logika Keamanan ---


// --- Middleware API Key (Inject Key for Public) ---
console.log("LOG: Memuat middleware API Key global (Injects key for public routes if missing)...");
app.use((req, res, next) => {
  const reqPath = req.path;
  let providedApiKey = req.query.apikey || req.headers['x-api-key'];

  // Skip checks
  const isPublicAssetOrSkipped = reqPath === '/' || reqPath === '/api/endpoint-status' || reqPath === '/api/submit-report' || reqPath === '/api/blacklist-info' || reqPath === '/api/my-ip' || reqPath === '/manage-blacklist' || reqPath.startsWith('/admin/') || reqPath.startsWith('/images/') || reqPath.startsWith('/audio/') || /\.(html|css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|map|mp3|json|txt)$/i.test(reqPath) || reqPath === '/favicon.ico';
  if (isPublicAssetOrSkipped) { return next(); }

  // Find Endpoint Definition
  let endpointDef = null; let endpointNeedsKey = false;
  for (const category in global.settings.endpoints) {
      const endpoints = global.settings.endpoints[category];
      if (Array.isArray(endpoints)) {
          const found = endpoints.find(e => e && e.path && typeof e.path === 'string' && reqPath === e.path.split('?')[0]);
          if (found) { endpointDef = found; if (endpointDef.path.includes("apikey=")) { endpointNeedsKey = true; } break; }
      }
  }

  // Apply Logic
  if (endpointDef) {
    if (endpointNeedsKey) { // Private
      if (!providedApiKey) { return res.status(401).json({ status: false, error: "API key dibutuhkan. Tambahkan ?apikey=KEY_ANDA" }); }
      if (global.apikey.includes(providedApiKey)) { return next(); }
      else { return res.status(403).json({ status: false, error: "API key tidak valid." }); }
    } else { // Public
      if (!providedApiKey && global.apikey && global.apikey.length > 0) { req.query.apikey = global.apikey[0]; }
      return next();
    }
  } else { return next(); } // Not defined
});
console.log(chalk.green("LOG: Middleware API Key global (Injects key for public) dimuat."));
// --- Akhir Middleware API Key ---


// --- Fungsi Bantuan GitHub API (Untuk admin.js) ---
const { GITHUB_USERNAME, GITHUB_REPO, GITHUB_TOKEN, GITHUB_FILE_PATH } = process.env;
const GITHUB_API_URL = GITHUB_USERNAME && GITHUB_REPO && GITHUB_FILE_PATH ? `https://api.github.com/repos/${GITHUB_USERNAME}/${GITHUB_REPO}/contents/${GITHUB_FILE_PATH}` : null;
const GITHUB_HEADERS = GITHUB_TOKEN ? { 'Authorization': `token ${GITHUB_TOKEN}`, 'Accept': 'application/vnd.github.v3+json', 'User-Agent': `${process.env.APP_NAME || 'Rikishopreal'}-API-Server/1.0` } : null;
let githubAdminConfigValid = !!(GITHUB_API_URL && GITHUB_HEADERS);
if (githubAdminConfigValid) console.log(chalk.green("LOG: Konfigurasi GitHub Admin ditemukan di .env."));
else console.warn(chalk.yellow("PERINGATAN: Konfigurasi GitHub Admin tidak lengkap/valid. Fitur admin blacklist/unblacklist via API akan GAGAL."));

async function getGitHubFileSha() {
  if (!githubAdminConfigValid) throw new Error('GITHUB: Konfigurasi API GitHub tidak valid atau tidak lengkap.');
  try {
    const response = await axios.get(GITHUB_API_URL, { headers: GITHUB_HEADERS, timeout: 10000 });
    return response.data.sha;
  } catch (error) {
    const status = error.response?.status;
    console.error(chalk.red(`GITHUB: Gagal mendapatkan SHA file: ${status || 'No Status'} - ${error.message}`));
    if (status === 404) { console.warn(chalk.yellow("GITHUB: File blacklist.json tidak ditemukan. Akan dibuat file baru saat update pertama.")); return null; }
    else if (status === 401 || status === 403) { console.error(chalk.red("GITHUB: Otentikasi gagal. Periksa GITHUB_TOKEN dan izinnya.")); throw new Error('GITHUB: Otentikasi gagal. Periksa GITHUB_TOKEN.'); }
    else if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) { throw new Error('GITHUB: Timeout saat mencoba mengambil SHA file.'); }
    throw new Error('Gagal mengambil informasi file dari GitHub.');
  }
}

async function updateGitHubFile(contentArray, commitMessage, sha) {
  if (!githubAdminConfigValid) throw new Error('GITHUB: Konfigurasi API GitHub tidak valid atau tidak lengkap.');
  const validContentArray = Array.isArray(contentArray) ? contentArray : [];
  const contentString = JSON.stringify(validContentArray, null, 2);
  const contentBase64 = Buffer.from(contentString).toString('base64');
  const payload = { message: commitMessage || `Update blacklist.json via API ${new Date().toISOString()}`, content: contentBase64, sha: sha };
  try {
    const response = await axios.put(GITHUB_API_URL, payload, { headers: GITHUB_HEADERS, timeout: 15000 });
    console.log(chalk.green(`GITHUB: File blacklist.json berhasil diupdate! Commit SHA: ${response.data?.commit?.sha}`));
    return true;
  } catch (error) {
    const status = error.response?.status;
    console.error(chalk.red(`GITHUB: Gagal mengupdate file: ${status || 'No Status'} - ${error.message}`));
    if (error.response) { console.error(chalk.red(`  -> GitHub Response: ${JSON.stringify(error.response.data)}`)); }
    if (status === 401 || status === 403) { throw new Error('GITHUB: Otentikasi gagal saat update. Periksa GITHUB_TOKEN.'); }
    else if (status === 409) { console.error(chalk.yellow("GITHUB: Konflik update (SHA mismatch). Coba lagi operasi admin.")); throw new Error('GITHUB: Konflik update terdeteksi. Silakan coba lagi.'); }
    else if (status === 422) { console.error(chalk.red("GITHUB: Payload update ditolak (Unprocessable Entity).")); throw new Error('GITHUB: Gagal memproses update file.'); }
    else if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) { throw new Error('GITHUB: Timeout saat mencoba mengupdate file.'); }
    throw new Error('Gagal mengupdate file ke GitHub.');
  }
}
if(githubAdminConfigValid) console.log(chalk.green("LOG: Fungsi helper GitHub API dimuat."));
// --- Akhir Fungsi Bantuan GitHub API ---


// --- Load Dynamic Routes (dari folder ./src dan admin.js) ---
let totalRoutes = 0;
const srcFolder = path.join(__dirname, './src');
console.log("LOG: Memulai memuat rute...");
try {
  // 1. Muat rute dari folder ./src (jika ada)
  if (fs.existsSync(srcFolder) && fs.statSync(srcFolder).isDirectory()) {
      fs.readdirSync(srcFolder).forEach((folderOrFile) => {
          const itemPath = path.join(srcFolder, folderOrFile);
          try {
              if (fs.statSync(itemPath).isDirectory()) {
                  fs.readdirSync(itemPath).forEach(file => {
                      if (path.extname(file) === '.js') {
                          const filePath = path.join(itemPath, file);
                          try { require(filePath)(app); totalRoutes++; }
                          catch (loadError) { console.error(chalk.red(`    ✗ GAGAL memuat rute: ${folderOrFile}/${file}. Error: ${loadError.message}`)); }
                      }
                  });
              } else if (path.extname(folderOrFile) === '.js' && folderOrFile !== 'admin.js') {
                  const filePath = itemPath;
                  try { require(filePath)(app); totalRoutes++; }
                  catch (loadError) { console.error(chalk.red(`    ✗ GAGAL memuat rute: ${folderOrFile}. Error: ${loadError.message}`)); }
              }
          } catch (statError) { console.error(chalk.red(` GAGAL membaca item di src: ${folderOrFile}. Error: ${statError.message}`)); }
      });
      console.log(chalk.green(`LOG: Selesai memuat rute dari folder 'src'.`));
  } else { console.warn(chalk.yellow("PERINGATAN: Folder './src' tidak ditemukan atau bukan direktori. Melewati pemuatan rute dari sana.")); }

  // 2. Muat rute admin secara eksplisit (cari di root atau src)
  const adminPaths = [path.join(__dirname, 'admin.js'), path.join(srcFolder, 'admin.js')]; let adminLoaded = false;
  for (const adminPath of adminPaths) {
      if (fs.existsSync(adminPath)) {
          try {
              console.log(`LOG: Mencoba memuat rute admin dari: ${path.relative(__dirname, adminPath)}...`);
              require(adminPath)(app, checkAdminKey, getGitHubFileSha, updateGitHubFile, sendDiscordAlert);
              adminLoaded = true;
              console.log(chalk.green(` ✓ Rute admin berhasil dimuat.`));
              break;
          } catch (loadError) { console.error(chalk.red(`   ✗ GAGAL memuat rute admin (${path.relative(__dirname, adminPath)}): ${loadError.message}`), loadError.stack); }
      }
  }
  if (!adminLoaded) { if (githubAdminConfigValid) { console.error(chalk.red("ERROR: File 'admin.js' tidak ditemukan, fitur admin tidak akan berfungsi.")); } else { console.warn(chalk.yellow("LOG: File 'admin.js' tidak ditemukan ATAU config GitHub tidak valid. Rute admin tidak dimuat.")); } }

  console.log(chalk.bgCyan.black.bold(' LOG: Pemuatan Rute Selesai '));
  console.log(chalk.cyan(` -> Total Rute Dinamis (non-admin) Dimuat: ${totalRoutes} `));
} catch (readDirError) { console.error(chalk.red(`FATAL ERROR: Gagal membaca direktori rute: ${readDirError.message}`)); process.exit(1); }
// --- Akhir Load Dynamic Routes ---


// --- Endpoint Laporan dari Frontend ---
app.post('/api/submit-report', (req, res) => {
    const { reportType, nama, teks } = req.body;
    const ip = req.ip;
    if (!reportType || typeof reportType !== 'string' || !teks || typeof teks !== 'string' || teks.trim().length === 0) { return res.status(400).json({ status: false, error: "Tipe laporan dan teks tidak boleh kosong." }); }
    const cleanText = teks.trim().substring(0, 1000);
    const cleanName = (nama && typeof nama === 'string') ? nama.trim().substring(0, 50) : 'Anonim';
    let webhookType;
    if (reportType === 'Lapor Error') { webhookType = 'report'; }
    else if (reportType === 'Request Fitur') { webhookType = 'feature'; }
    else { console.warn(chalk.yellow(`Laporan Ditolak: Tipe tidak valid '${reportType}' dari IP: ${ip}`)); return res.status(400).json({ status: false, error: "Tipe laporan tidak valid." }); }
    sendDiscordAlert(webhookType, { nama: cleanName, teks: cleanText, ip: ip });
    console.log(`LAPORAN: ${reportType} diterima dari ${cleanName} (IP: ${ip})`);
    res.status(200).json({ status: true, message: `Terima kasih! ${reportType} Anda telah berhasil dikirim.` });
});
console.log(chalk.green("LOG: Endpoint '/api/submit-report' dimuat."));
// --- Akhir Endpoint Laporan ---


// --- Rute Lainnya (Status, Info Blacklist, Root, My IP, Admin Page) ---
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'api-page', 'index.html'), (err) => {
        if (err) { console.error(chalk.red(`Error mengirim index.html: ${err.message}`)); res.status(404).type('text/plain').send("404 Not Found: Halaman utama tidak ditemukan."); }
    });
});
console.log("LOG: Rute default '/' untuk frontend dikonfigurasi.");

app.get('/api/endpoint-status', (req, res) => {
    // Kembalikan status dari settings.json (lebih reliable di Vercel)
    let staticStatus = {};
     try {
         for (const category in global.settings.endpoints) {
            if (Array.isArray(global.settings.endpoints[category])) {
                global.settings.endpoints[category].forEach(endpoint => {
                    if (endpoint && endpoint.path) {
                        const basePath = endpoint.path.split('?')[0];
                        staticStatus[basePath] = endpoint.status || 'Active';
                    }
                });
            }
         }
     } catch (e) { console.error("Error reading status from settings in /api/endpoint-status:", e); }
    res.json({ data: staticStatus });
});
console.log("LOG: Rute '/api/endpoint-status' dikonfigurasi (mengembalikan status dari settings.json).");

app.get('/api/blacklist-info', async (req, res) => { // Buat jadi async
  try {
    const currentBlacklist = await fetchBlacklistAndReturnSet(); // Ambil data terbaru
    const maskedIPs = Array.from(currentBlacklist).map(ip => {
        if (typeof ip !== 'string') return 'invalid_entry';
        if (ip.includes(':')) { const parts = ip.split(':'); return parts.length > 3 ? parts.slice(0, 3).join(':') + ':xxxx:...' : ip; }
        else { const parts = ip.split('.'); return parts.length === 4 ? parts.slice(0, 3).join('.') + '.xxx' : ip; }
    }).filter(ip => ip !== 'invalid_entry');
    res.status(200).json({ status: true, count: maskedIPs.length, data: maskedIPs });
  } catch (error) { console.error(chalk.red(`Error di /api/blacklist-info: ${error.message}`), error); res.status(500).json({ status: false, error: 'Gagal memproses daftar blacklist.' }); }
});
console.log(chalk.green("LOG: Rute '/api/blacklist-info' dikonfigurasi (fetch terbaru)."));

app.get('/api/my-ip', (req, res) => { res.status(200).json({ status: true, ip: req.ip }); });
console.log(chalk.green("LOG: Rute '/api/my-ip' dikonfigurasi."));

app.get('/manage-blacklist', (req, res) => {
    const adminPagePath = path.join(__dirname, 'api-page', 'admin.html');
    res.sendFile(adminPagePath, (err) => {
        if (err) { console.error(chalk.red(`ADMIN PAGE: Gagal mengirim admin.html: ${err.message}`)); res.status(404).type('text/plain').send("404 Not Found: Halaman admin tidak ditemukan."); }
    });
});
console.log(chalk.green("LOG: Rute '/manage-blacklist' untuk halaman admin dikonfigurasi."));
// --- Akhir Rute Lainnya ---


// --- Error Handlers (HARUS DI BAGIAN PALING AKHIR setelah semua rute) ---
// Handler 404 - Not Found
app.use((req, res, next) => {
    if (!/\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|map|mp3|json|txt|html)$/i.test(req.path) && req.path !== '/favicon.ico') { console.warn(chalk.yellow(`404 Not Found: ${req.method} ${req.originalUrl} (IP: ${req.ip})`)); }
    const fourOhFourPath = path.join(__dirname, 'api-page', '404.html');
    res.status(404).sendFile(fourOhFourPath, (err) => {
        if (err) {
             const fallbackPath = path.join(__dirname, '404.html');
             res.sendFile(fallbackPath, (fallbackErr) => {
                 if (fallbackErr) { res.type('text/plain').send('404 Not Found'); }
             });
        }
    });
});
console.log("LOG: Handler 404 (Not Found) dikonfigurasi.");

// Handler 500 - Internal Server Error
app.use((err, req, res, next) => {
    console.error(chalk.red.bold('\n!!! INTERNAL SERVER ERROR (500) !!!'));
    console.error(chalk.red(`Timestamp: ${new Date().toISOString()}`));
    console.error(chalk.red(`Request: ${req.method} ${req.originalUrl} (IP: ${req.ip})`));
    console.error(err.stack || err.message || err);

    // Kirim notifikasi Discord
    sendDiscordAlert('error', { ip: req.ip, endpoint: req.originalUrl || req.path, errorMessage: err.message || 'Internal Server Error' });

    // Jangan coba update status endpoint di Vercel

    if (res.headersSent) { console.error(chalk.red(" -> Headers sudah terkirim, tidak bisa mengirim respons error 500.")); return next(err); }

    // Kirim respons 500
    const fiveHundredPath = path.join(__dirname, 'api-page', '500.html');
    res.status(500).sendFile(fiveHundredPath, (fileErr) => {
        if (fileErr) {
             const fallbackPath500 = path.join(__dirname, '500.html');
             res.sendFile(fallbackPath500, (fallbackErr) => {
                 if (fallbackErr) { res.type('text/plain').send('500 Internal Server Error'); }
             });
        }
    });
});
console.log("LOG: Handler 500 (Internal Server Error) dikonfigurasi.");
// --- Akhir Error Handlers ---


// --- Start Server (Disesuaikan untuk Vercel) ---
// Vercel akan menangani listening secara otomatis di production
if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) { // Cek juga VERCEL env var
    console.log("LOG: Menjalankan server Express untuk development lokal...");
    const server = app.listen(PORT, '0.0.0.0', () => {
        const address = server.address();
        if (!address) { console.error(chalk.red.bold(`FATAL: Gagal mendapatkan address server setelah listen di port ${PORT}.`)); process.exit(1); }
        const actualPort = address.port;
        // Tentukan protokol hanya berdasarkan NODE_ENV untuk log
        const protocol = (process.env.NODE_ENV === 'production' ? 'https' : 'http');
        const hostnameSetting = global.settings?.publicAddress;
        const displayHostname = (hostnameSetting && hostnameSetting !== '0.0.0.0') ? hostnameSetting : 'localhost';
        const portString = (protocol === 'http' && actualPort === 80) || (protocol === 'https' && actualPort === 443) ? '' : `:${actualPort}`;
        const accessibleUrl = `${protocol}://${displayHostname}${portString}`;
        const localUrl = `http://localhost:${actualPort}`;
        const networkIp = '0.0.0.0';

        console.log(chalk.bgGreen.black.bold(' ✓ Server BERHASIL berjalan! '));
        console.log(chalk.cyan(` -> Lokal:      ${localUrl} `));
        if (displayHostname !== networkIp && displayHostname === 'localhost') { console.log(chalk.cyan(` -> Jaringan:   http://${networkIp}:${actualPort} `)); }
        if (displayHostname !== 'localhost') { console.log(chalk.cyan(` -> Publik (?): ${accessibleUrl} `)); }
        console.log(chalk.magenta(` -> Mendengarkan di port aktual: ${actualPort} `));
    });
    server.on('error', (error) => {
        console.error(chalk.red.bold('!!! FATAL ERROR SAAT MENJALANKAN SERVER LOKAL !!! 💥'));
        if (error.syscall !== 'listen') { throw error; }
        const bind = typeof PORT === 'string' ? 'Pipe ' + PORT : 'Port ' + PORT;
        switch (error.code) {
            case 'EACCES': console.error(chalk.red(`${bind} memerlukan hak akses lebih tinggi.`)); process.exit(1); break;
            case 'EADDRINUSE': console.error(chalk.red(`${bind} (atau port ${error.port}) sudah digunakan.`)); process.exit(1); break;
            default: console.error(chalk.red(`Error tidak dikenal saat listen:`), error); throw error;
        }
    });
} else {
    console.log("LOG: Server siap dijalankan oleh Vercel (atau environment production lainnya).");
}
// --- Akhir Start Server ---


// --- Global Unhandled Exception & Rejection Handlers ---
process.on('uncaughtException', (err, origin) => {
  console.error(chalk.red.bold('\n!!! UNCAUGHT EXCEPTION !!! 💥'));
  console.error(chalk.red(`Timestamp: ${new Date().toISOString()}`));
  console.error(chalk.red(`Origin: ${origin}`));
  console.error(err.stack || err);
  // process.exit(1); // Pertimbangkan exit di production
});
process.on('unhandledRejection', (reason, promise) => {
  console.error(chalk.red.bold('\n!!! UNHANDLED PROMISE REJECTION !!! 💥'));
  console.error(chalk.red(`Timestamp: ${new Date().toISOString()}`));
  console.error(chalk.red('Reason:'), reason);
});
// --- Akhir Global Handlers ---

console.log("\nLOG: Konfigurasi server selesai.");

// Export 'app' untuk Vercel (atau serverless lainnya)
module.exports = app;
// --- AKHIR FILE index.js ---
