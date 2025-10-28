const axios = require('axios');

module.exports = function(app) {
    // Fungsi scrape di dalam module.exports
    async function scrape() {
        try {
            const getRandomAyah = () => Math.floor(Math.random() * 6236) + 1;
            const ayahNumber = getRandomAyah();
            const url = `https://api.alquran.cloud/v1/ayah/${ayahNumber}/ar.alafasy`; // Hapus proxy() jika tidak ada

            console.log(`Fetching surah data for ayah: ${ayahNumber}`); // Log untuk debug

            const response = await axios.get(url, {
                timeout: 30000,
                headers: { "User-Agent": "Mozilla/5.0" },
            });

            // Periksa status dan struktur data
            if (response.status === 200 && response.data && response.data.code === 200 && response.data.data) {
                // Ekstrak hanya data yang relevan (misalnya: teks, surah, audio)
                const { text, audio } = response.data.data;
                const { number, name, englishName, englishNameTranslation, revelationType } = response.data.data.surah;
                return {
                    audio: audio,
                    text: text,
                    surah: {
                        number: number,
                        name: name,
                        englishName: englishName,
                        englishNameTranslation: englishNameTranslation,
                        revelationType: revelationType
                    },
                    ayahNumberInSurah: response.data.data.numberInSurah, // Nomor ayat dalam surah
                    juz: response.data.data.juz
                };
            } else {
                // Log respons jika tidak sesuai harapan
                console.error("Unexpected response structure from alquran.cloud:", response.data);
                throw new Error(`Data tidak ditemukan atau format respons API Alquran tidak valid (Status: ${response.status}, Code: ${response.data?.code})`);
            }
        } catch (error) {
            console.error("API Error (tebaksurah scrape):", error.message);
            // Lempar error asli jika ada, atau error umum
            throw error.response?.data?.error || error.message || new Error("Gagal mengambil data Surah");
        }
    }

    const handleRequest = async (req, res) => {
        try {
            const apikey = req.method === 'GET' ? req.query.apikey : req.body.apikey;
            if (!global.apikey.includes(apikey)) {
                return res.json({ status: false, error: 'Apikey invalid' });
            }
            const result = await scrape();
            res.json({ status: true, result: result });
        } catch (error) {
            console.error(`[tebaksurah ${req.method}] Error:`, error.message);
            res.status(500).send(`Error: ${error.message}`);
        }
    };

    // --- PATH DIUBAH DI SINI (sesuaikan dengan endpoint di .ts) ---
    app.get('/games/surah', handleRequest);
    app.post('/games/surah', handleRequest);
    // --- AKHIR PERUBAHAN PATH ---
};
