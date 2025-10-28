/*
 • Fitur By Anomaki Team
 • Created : xyzan code (sesuai kode yang diberikan)
 • All-in-one Downloader (scrape from aio-downloader-one.vercel.app)
 • Disesuaikan oleh Gemini
*/
const axios = require('axios');

/**
 * Mengunduh konten dari berbagai platform menggunakan API aio-downloader-one.vercel.app.
 * @param {string} url - URL konten yang ingin diunduh (misal: YouTube, TikTok, dll).
 * @returns {Promise<object>} Objek yang berisi status, creator, dan hasil unduhan.
 */
async function alldl(url) {
    try {
        const endpoint = "https://aio-downloader-one.vercel.app/api/aio";
        const params = { url };

        const response = await axios.get(endpoint, { 
            params, 
            timeout: 20000 // Timeout 20 detik
        });
        const data = response.data;

        if (!data || !data.status) {
            // Jika API eksternal merespons tapi statusnya false atau data.data kosong
            throw new Error(data.message || "Gagal mengambil data dari AIO Downloader API.");
        }

        // Mengembalikan data dalam format yang konsisten dengan API Anda
        return {
            creator: "deff", // Sesuai dengan creator di kode asli
            status: true,
            result: data.data // Ambil langsung properti 'data' dari respons API eksternal
        };

    } catch (err) {
        let errorMessage = "Terjadi kesalahan saat berkomunikasi dengan AIO Downloader API.";
        if (err.response) {
            // Error dari respons server (misal: 404, 500 dari aio-downloader-one.vercel.app)
            errorMessage = `AIO Downloader API mengembalikan status: ${err.response.status}. Pesan: ${JSON.stringify(err.response.data)}`;
        } else if (err.request) {
            // Request dibuat tapi tidak ada respons (timeout atau masalah jaringan)
            errorMessage = "Tidak ada respons dari AIO Downloader API. Periksa koneksi atau status API.";
        } else {
            // Error lainnya
            errorMessage = err.message;
        }
        
        console.error("Error di alldl scraper:", errorMessage);
        throw new Error(errorMessage); // Dilempar agar dapat ditangani di route handler
    }
}

// Mengekspor fungsi yang menerima object 'app' dari Express
module.exports = function (app) {
    // Mendefinisikan route untuk endpoint All-in-one Downloader
    app.get('/download/alldl', async (req, res) => {
        try {
            const { url, apikey } = req.query;

            // Validasi API Key
            if (!global.apikey.includes(apikey)) {
                return res.status(403).json({ status: false, error: 'Apikey invalid' });
            }
            // Validasi parameter URL
            if (!url) {
                return res.status(400).json({ status: false, error: 'Parameter url diperlukan' });
            }

            // Memanggil fungsi scraper alldl
            const results = await alldl(url);
            
            // Mengirim hasil dalam format JSON standar Anda
            res.status(200).json({
                status: true,
                result: results.result // Ambil properti 'result' dari hasil alldl
            });
        } catch (error) {
            // Menangani error dari scraper dan mengirim respons yang sesuai
            console.error("Error di route /download/alldl:", error); 
            res.status(500).json({
                status: false,
                message: "Terjadi kesalahan pada server saat mencoba mengunduh.",
                error: error.message
            });
        }
    });
};

