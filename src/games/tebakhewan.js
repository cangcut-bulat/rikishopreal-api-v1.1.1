const axios = require('axios');
const cheerio = require('cheerio'); // Jangan lupa require cheerio

module.exports = function(app) {
    async function scrape() {
        // Ambil halaman acak antara 1 dan 20
        const page = Math.floor(20 * Math.random()) + 1;
        const url = `https://rimbakita.com/daftar-nama-hewan-lengkap/${page}/`;

        try {
            const response = await axios.get(url, {
                timeout: 30000,
                headers: { "User-Agent": "Mozilla/5.0" },
            });
            const html = response.data;
            const $ = cheerio.load(html);

            // Scrape data gambar dan judul
            const json = $("div.entry-content.entry-content-single img[class*=wp-image-][data-src]")
              .map((_, el) => {
                const src = $(el).attr("data-src");
                if (!src) return null;
                const titleMatch = src.split("/").pop();
                const title = titleMatch ? titleMatch.replace(/-/g, " ").replace(/\.\w+$/, "") : "Unknown Animal"; // Hapus ekstensi file
                return {
                  title: title.charAt(0).toUpperCase() + title.slice(1), // Kapitalisasi
                  url: src,
                };
              })
              .get()
              .filter((item) => item !== null); // Hapus hasil null

            if (json.length === 0) {
                throw new Error("Tidak ada data hewan ditemukan di halaman yang di-scrape");
            }

            // Ambil satu hewan acak dari hasil scrape halaman
            return json[Math.floor(Math.random() * json.length)];

        } catch (error) {
            console.error("API Error (tebakhewan scrape):", error.message);
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
            console.error(`[tebakhewan ${req.method}] Error:`, error.message);
            res.status(500).send(`Error: ${error.message}`);
        }
    };

    app.get('/games/tebakhewan', handleRequest); // Path diubah
    app.post('/games/tebakhewan', handleRequest); // Path diubah
};
