
const axios = require('axios');

/**
 * Mengunduh lagu dari Spotify menggunakan API acethinker.com.
 * @param {string} url - URL lagu Spotify.
 * @returns {Promise<object>} Objek JSON dari API.
 */
async function spotifyDownloader(url) {
    try {
        const response = await axios.get(
            `https://www.acethinker.com/downloader/api/jdownv2.php?url=${encodeURIComponent(url)}`, 
            {
                headers: {
                    'Accept': 'application/json, text/plain, */*',
                    'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36',
                    'Referer': 'https://www.acethinker.com/spotify-mp3'
                }
            }
        );

        // Jika respons tidak memiliki data atau properti 'error', lempar error
        if (!response.data || response.data.error) {
           throw new Error(response.data.error || 'Tidak ada data yang diterima dari API eksternal.');
        }

        return response.data;

    } catch (e) {
        // Melempar error agar bisa ditangkap oleh block catch di route handler
        throw new Error(e.message);
    }
}

// Mengekspor fungsi yang menerima object 'app' dari Express
module.exports = function (app) {
    // Mendefinisikan route untuk endpoint downloader Spotify
    app.get('/download/spotify', async (req, res) => {
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
            const results = await spotifyDownloader(url);
            
            // Mengirim hasil dalam format JSON standar Anda
            res.status(200).json({
                status: true,
                result: results
            });
        } catch (error) {
            // Menangani error dari scraper dan mengirim respons yang sesuai
            console.error(error); 
            res.status(500).json({
                status: false,
                message: "Terjadi kesalahan pada server saat mencoba mengunduh.",
                error: error.message
            });
        }
    });
}
