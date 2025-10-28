const axios = require('axios');

module.exports = function(app) {
    // Helper function di dalam module.exports
    async function scrape() {
        try {
            const response = await axios.get(
              "https://raw.githubusercontent.com/BochilTeam/database/master/games/family100.json",
              {
                timeout: 30000,
                headers: { "User-Agent": "Mozilla/5.0" }, // User agent simpel
              }
            );
            const src = response.data;
            if (!Array.isArray(src) || src.length === 0) {
                throw new Error("Data sumber Family 100 kosong atau tidak valid");
            }
            // Ambil data acak
            return src[Math.floor(Math.random() * src.length)];
        } catch (error) {
            console.error("API Error (family100 scrape):", error.message);
            // Lempar error agar ditangkap oleh handler rute
            throw error;
        }
    }

    // Handler Rute GET dan POST
    const handleRequest = async (req, res) => {
        try {
            // 1. Validasi API Key (sesuai contoh)
            const apikey = req.method === 'GET' ? req.query.apikey : req.body.apikey;
            if (!global.apikey.includes(apikey)) {
                return res.json({ status: false, error: 'Apikey invalid' });
            }

            // 2. Panggil helper
            const result = await scrape();

            // 3. Kirim Respons Sukses (sesuai contoh)
            res.json({
                status: true,
                result: result
            });

        } catch (error) {
            // 4. Tangani Error (sesuai contoh)
            console.error(`[family100 ${req.method}] Error:`, error.message); // Log server
            res.status(500).send(`Error: ${error.message}`);
        }
    };

    // --- PATH DIUBAH DI SINI ---
    app.get('/games/family100', handleRequest);
    app.post('/games/family100', handleRequest);
    // --- AKHIR PERUBAHAN PATH ---
};
