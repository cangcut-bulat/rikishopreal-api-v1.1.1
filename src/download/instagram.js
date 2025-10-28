/*
 • Instagram Downloader HD
 • API from api.yupra.my.id
 • WM: Naufal YP
 • Disesuaikan untuk Express API oleh Gemini
*/
const axios = require('axios');

/**
 * Mengunduh media (video/gambar) dari Instagram menggunakan API eksternal.
 * @param {string} url - URL postingan Instagram (reel, post, etc.).
 * @returns {Promise<object>} Objek yang berisi hasil dari API.
 */
async function instagramDownloader(url) {
    try {
        const apiUrl = `https://api.yupra.my.id/api/downloader/Instagram`;
        
        // Menggunakan axios yang sudah menjadi dependensi di proyek Anda
        const response = await axios.get(apiUrl, {
            params: {
                url: url // axios akan meng-encode URL secara otomatis
            }
        });

        const json = response.data;

        // Validasi respons dari API eksternal
        if (json.status !== 200 || !json.result || !json.result.medias || json.result.medias.length === 0) {
            throw new Error(json.message || 'Gagal mengambil data atau tidak ada media yang ditemukan dari API.');
        }

        return json.result;

    } catch (error) {
        let errorMessage = "Terjadi kesalahan saat mengambil data dari API Instagram Downloader.";
        if (error.response) {
            // Menangkap error jika API eksternal mengembalikan status error (4xx, 5xx)
            errorMessage = `API eksternal mengembalikan error: ${error.response.status} - ${JSON.stringify(error.response.data)}`;
        } else {
            errorMessage = error.message;
        }
        console.error("Scraper Error (Instagram):", errorMessage);
        throw new Error(errorMessage);
    }
}

// Mengekspor fungsi yang menerima object 'app' dari Express
module.exports = function (app) {
    app.get('/download/instagram', async (req, res) => {
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

            // Memanggil fungsi scraper
            const results = await instagramDownloader(url);
            
            // Mengirim hasil dalam format JSON standar Anda
            res.status(200).json({
                status: true,
                result: results
            });
        } catch (error) {
            // Menangani error dari scraper dan mengirim respons yang sesuai
            res.status(500).json({
                status: false,
                message: "Terjadi kesalahan pada server saat mencoba mengunduh dari Instagram.",
                error: error.message
            });
        }
    });
};

