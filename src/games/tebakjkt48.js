const axios = require('axios');

module.exports = function(app) {
    async function scrape() {
        try {
            const response = await axios.get(
              "https://raw.githubusercontent.com/siputzx/tebak-jkt/refs/heads/main/tebak.json",
              { timeout: 30000, headers: { "User-Agent": "Mozilla/5.0" } }
            );
            const src = response.data;
             if (!Array.isArray(src) || src.length === 0) {
                throw new Error("Data sumber Tebak JKT48 kosong atau tidak valid");
            }
            return src[Math.floor(Math.random() * src.length)];
        } catch (error) {
            console.error("API Error (tebakjkt48 scrape):", error.message);
            throw error;
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
            console.error(`[tebakjkt48 ${req.method}] Error:`, error.message);
            res.status(500).send(`Error: ${error.message}`);
        }
    };

    // --- PATH DIUBAH DI SINI (sesuaikan dgn endpoint .ts) ---
    app.get('/games/tebakjkt', handleRequest);
    app.post('/games/tebakjkt', handleRequest);
    // --- AKHIR PERUBAHAN PATH ---
};
