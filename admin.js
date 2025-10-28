const chalk = require('chalk');
// axios tidak lagi dibutuhkan di sini karena fungsi GitHub sudah dipindah ke index.js

// Terima semua dependensi sebagai argumen
module.exports = function (app, checkAdminKey, getGitHubFileSha, updateGitHubFile, sendDiscordAlert) {

  // Validasi dependensi saat modul dimuat
  if (typeof checkAdminKey !== 'function' ||
      typeof getGitHubFileSha !== 'function' ||
      typeof updateGitHubFile !== 'function' ||
      typeof sendDiscordAlert !== 'function') {
     console.error(chalk.red("FATAL ADMIN ROUTE ERROR: Dependensi (middleware/helper/sendDiscordAlert) tidak diteruskan dengan benar ke admin.js!"));
     // Hentikan pemuatan rute ini jika dependensi penting hilang
     // (atau lemparkan error agar server tahu ada masalah konfigurasi)
     throw new Error("Gagal memuat rute admin karena dependensi hilang.");
  }

  // --- Rute Admin (Semua rute di sini memerlukan checkAdminKey) ---

  /**
   * [GET /admin/list]
   * Mengembalikan daftar lengkap IP yang saat ini ada di blacklist (dari memori global).
   * Memerlukan header X-Admin-Key yang valid.
   */
  app.get('/admin/list', checkAdminKey, (req, res) => {
    try {
        // Baca langsung dari Set di memori global (lebih cepat)
        const ipList = Array.from(global.blacklistedIPs || new Set()); // Ambil dari global, pastikan ada Set kosong jika belum terdefinisi
        res.status(200).json({
          status: true,
          count: ipList.length,
          data: ipList // Kirim daftar IP asli (tidak disamarkan)
        });
    } catch (error) {
        console.error(chalk.red(`ADMIN /list Error: ${error.message}`), error);
        res.status(500).json({ status: false, error: "Gagal mengambil daftar blacklist internal." });
    }
  });

  /**
   * [POST /admin/blacklist?ip=...]
   * Menambahkan IP address ke daftar blacklist (memori dan GitHub).
   * Memerlukan header X-Admin-Key yang valid dan query parameter 'ip'.
   */
  app.post('/admin/blacklist', checkAdminKey, async (req, res) => {
    const { ip } = req.query; // Ambil IP dari query parameter

    // Validasi input IP (sederhana)
    if (!ip || typeof ip !== 'string' || ip.trim() === '') {
      return res.status(400).json({ status: false, error: "Parameter query 'ip' dibutuhkan dan tidak boleh kosong." });
    }
    const cleanIp = ip.trim(); // Bersihkan spasi di awal/akhir

    // Cek apakah IP sudah ada di memori
    if (global.blacklistedIPs && global.blacklistedIPs.has(cleanIp)) {
      return res.status(400).json({ status: false, message: `IP ${cleanIp} sudah ada di blacklist.` });
    }

    try {
      console.log(chalk.yellow(`ADMIN (IP: ${req.ip}): Memproses penambahan blacklist untuk IP ${cleanIp}...`));

      // 1. Dapatkan SHA terbaru dari file di GitHub (untuk update)
      const currentSha = await getGitHubFileSha();

      // 2. Buat daftar baru (ambil dari global, tambahkan IP baru, pastikan unik)
      const currentList = Array.from(global.blacklistedIPs || new Set());
      currentList.push(cleanIp);
      const newList = [...new Set(currentList)]; // Gunakan Set untuk otomatis handle duplikat

      // 3. Update file di GitHub
      const commitMessage = `[ADMIN] Blacklist IP: ${cleanIp}`;
      await updateGitHubFile(newList, commitMessage, currentSha); // Panggil fungsi helper dari index.js

      // 4. Update Set di memori global (penting agar langsung aktif)
      if (!global.blacklistedIPs) { global.blacklistedIPs = new Set(); } // Inisialisasi jika belum ada
      global.blacklistedIPs.add(cleanIp);
      console.log(chalk.green(`ADMIN (IP: ${req.ip}): IP ${cleanIp} berhasil ditambahkan ke blacklist (memori & GitHub).`));

      // 5. Kirim Notifikasi Discord
      sendDiscordAlert('blacklist_action', {
          action: 'blacklisted', // Tipe aksi
          ip: cleanIp,          // IP yang di-blacklist
          adminIp: req.ip       // IP admin yang melakukan
      });

      // 6. Kirim respons sukses ke client
      res.status(200).json({ status: true, message: `IP ${cleanIp} berhasil ditambahkan ke blacklist.` });

    } catch (error) {
      console.error(chalk.red(`ADMIN: Gagal mem-blacklist IP ${cleanIp}: ${error.message}`), error);
      // Berikan pesan error yang lebih informatif ke client
      const errorMessage = error.message.includes('GITHUB')
        ? 'Gagal mengupdate file di GitHub. Periksa log server dan konfigurasi GitHub.'
        : 'Terjadi kesalahan internal saat memproses blacklist.';
      res.status(500).json({ status: false, error: errorMessage, details: error.message });
    }
  });

  /**
   * [POST /admin/unblacklist?ip=...]
   * Menghapus IP address dari daftar blacklist (memori dan GitHub).
   * Memerlukan header X-Admin-Key yang valid dan query parameter 'ip'.
   */
  app.post('/admin/unblacklist', checkAdminKey, async (req, res) => {
    const { ip } = req.query; // Ambil IP dari query parameter

    // Validasi input IP
    if (!ip || typeof ip !== 'string' || ip.trim() === '') {
      return res.status(400).json({ status: false, error: "Parameter query 'ip' dibutuhkan dan tidak boleh kosong." });
    }
    const cleanIp = ip.trim();

    // Cek apakah IP ada di memori
    if (!global.blacklistedIPs || !global.blacklistedIPs.has(cleanIp)) {
      return res.status(400).json({ status: false, message: `IP ${cleanIp} tidak ditemukan di daftar blacklist.` });
    }

    try {
      console.log(chalk.yellow(`ADMIN (IP: ${req.ip}): Memproses penghapusan blacklist untuk IP ${cleanIp}...`));

      // 1. Dapatkan SHA terbaru dari file di GitHub
      const currentSha = await getGitHubFileSha();
      // Peringatan jika file tidak ada di GitHub tapi IP ada di memori (kasus aneh)
      if (currentSha === null) {
          console.warn(chalk.yellow(`ADMIN UNBLACKLIST: File GitHub tidak ditemukan (SHA null), tapi IP ${cleanIp} ada di memori. Mencoba membuat file baru tanpa IP ini.`));
      }

      // 2. Update Set di memori global (hapus IP)
      global.blacklistedIPs.delete(cleanIp);
      // Buat array baru dari Set yang sudah diupdate
      const newList = Array.from(global.blacklistedIPs);

      // 3. Update file di GitHub
      const commitMessage = `[ADMIN] Unblacklist IP: ${cleanIp}`;
      await updateGitHubFile(newList, commitMessage, currentSha); // Panggil fungsi helper dari index.js

      // 4. Log sukses
      console.log(chalk.green(`ADMIN (IP: ${req.ip}): IP ${cleanIp} berhasil dihapus dari blacklist (memori & GitHub).`));

      // 5. Kirim Notifikasi Discord
      sendDiscordAlert('blacklist_action', {
          action: 'unblacklisted', // Tipe aksi
          ip: cleanIp,            // IP yang di-unblacklist
          adminIp: req.ip         // IP admin yang melakukan
      });

      // 6. Kirim respons sukses ke client
      res.status(200).json({ status: true, message: `IP ${cleanIp} berhasil dihapus dari blacklist.` });

    } catch (error) {
      console.error(chalk.red(`ADMIN: Gagal meng-unblacklist IP ${cleanIp}: ${error.message}`), error);
      // Jika update GitHub gagal, tambahkan kembali IP ke memori agar konsisten
       if (global.blacklistedIPs && !global.blacklistedIPs.has(cleanIp)) { // Cek jika belum ada lagi
           global.blacklistedIPs.add(cleanIp);
           console.warn(chalk.yellow(`ADMIN: Rollback - IP ${cleanIp} ditambahkan kembali ke memori karena update GitHub gagal.`));
       }
      // Berikan pesan error ke client
      const errorMessage = error.message.includes('GITHUB')
        ? 'Gagal mengupdate file di GitHub. Periksa log server dan konfigurasi GitHub.'
        : 'Terjadi kesalahan internal saat memproses unblacklist.';
      res.status(500).json({ status: false, error: errorMessage, details: error.message });
    }
  });

  console.log(chalk.cyan("✓ Rute Admin (/admin/list, /admin/blacklist, /admin/unblacklist) dengan Log Discord dimuat."));
}; // Akhir dari module.exports
