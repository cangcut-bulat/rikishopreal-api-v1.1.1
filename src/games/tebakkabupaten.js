const axios = require('axios');
const cheerio = require('cheerio'); // Jangan lupa require cheerio

module.exports = function(app) {
    const baseUrl = "https://id.m.wikipedia.org";

    // Fungsi untuk fetch gambar (dipindah ke dalam module.exports)
    async function fetchImageUrl(url) {
        try {
            const response = await axios.get(url, {
                timeout: 30000,
                headers: { "User-Agent": "Mozilla/5.0" },
            });
            const html = response.data;
            const $ = cheerio.load(html);
            // Selector mungkin perlu disesuaikan jika struktur Wikipedia berubah
            const src = $("a.mw-file-description img.mw-file-element").first().attr("src");
            return src ? "https:" + src : null;
        } catch (error) {
            console.error("Error fetching image URL for:", url, error.message);
            return null; // Kembalikan null jika gagal fetch gambar
        }
    }

    // Fungsi scrape utama
    async function scrape() {
        try {
            const response = await axios.get(baseUrl + "/wiki/Daftar_kabupaten_di_Indonesia", {
                timeout: 30000,
                headers: { "User-Agent": "Mozilla/5.0" },
            });
            const html = response.data;
            const $ = cheerio.load(html);
            const kabupatenList = $("table.wikitable td a[href^='/wiki/Kabupaten']") // Lebih spesifik ke tabel
              .map((_, element) => {
                const link = $(element).attr("href");
                const name = $(element).attr("title");
                // Tambah validasi dasar
                if (link && name && link.startsWith('/wiki/Kabupaten')) {
                    return { link: baseUrl + link, name: name };
                }
                return null;
              })
              .get()
              .filter((item) => item !== null);

            if (kabupatenList.length === 0) {
                throw new Error("Tidak ada kabupaten ditemukan di halaman Wikipedia");
            }

            const randomKabupaten = kabupatenList[Math.floor(Math.random() * kabupatenList.length)];
            const imageUrl = await fetchImageUrl(randomKabupaten.link);
            const judulBaru = randomKabupaten.name.replace("Kabupaten ", "").trim();
            // Coba ambil resolusi lebih besar (opsional, mungkin tidak selalu ada)
            const ukuranBaru = imageUrl ? imageUrl.replace(/\/\d+px-/, "/1080px-") : null;

            return {
                link: randomKabupaten.link,
                title: judulBaru,
                url: ukuranBaru || imageUrl, // Fallback ke URL asli jika 1080px tidak ada
            };
        } catch (error) {
            console.error("API Error (tebakkabupaten scrape):", error.message);
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
            console.error(`[tebakkabupaten ${req.method}] Error:`, error.message);
            res.status(500).send(`Error: ${error.message}`);
        }
    };

    app.get('/games/kabupaten', handleRequest); // Path endpoint dari .ts
    app.post('/games/kabupaten', handleRequest); // Path endpoint dari .ts
};
