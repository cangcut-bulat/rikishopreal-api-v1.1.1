const axios = require('axios');

module.exports = function(app) {
    async function scrape() {
      try {
        const response = await axios.get("https://flagcdn.com/en/codes.json", { timeout: 15000, headers: { "User-Agent": "Mozilla/5.0" } });
        const data = response.data;
        if (typeof data !== 'object' || Object.keys(data).length === 0) { throw new Error("Data codes.json tidak valid"); }
        const randomKey = Object.keys(data)[Math.floor(Math.random() * Object.keys(data).length)];
        return { name: data[randomKey], img: `https://flagpedia.net/data/flags/ultra/${randomKey}.png` };
      } catch (error) {
        console.warn("Primary flag API failed, trying fallback:", error.message);
        try {
          const srcResponse = await axios.get("https://raw.githubusercontent.com/BochilTeam/database/master/games/tebakbendera2.json", { timeout: 15000, headers: { "User-Agent": "Mozilla/5.0" } });
          const src = srcResponse.data;
           if (!Array.isArray(src) || src.length === 0) { throw new Error("Data fallback tebakbendera2.json kosong atau tidak valid"); }
          return src[Math.floor(Math.random() * src.length)];
        } catch (innerError) { console.error("API Error (tebakbendera fallback):", innerError.message); throw innerError; }
      }
    }

    const handleRequest = async (req, res) => {
        try {
            const apikey = req.method === 'GET' ? req.query.apikey : req.body.apikey;
            if (!global.apikey.includes(apikey)) { return res.json({ status: false, error: 'Apikey invalid' }); }
            const result = await scrape();
            res.json({ status: true, result: result });
        } catch (error) { console.error(`[tebakbendera ${req.method}] Error:`, error.message); res.status(500).send(`Error: ${error.message}`); }
    };

    // --- PATH DIUBAH DI SINI ---
    app.get('/games/tebakbendera', handleRequest);
    app.post('/games/tebakbendera', handleRequest);
    // --- AKHIR PERUBAHAN PATH ---
};
