const ytdl = require('@vreden/youtube_scraper');

module.exports = function (app) {
  app.get('/download/ytmp3', async (req, res) => {
    try {
      const { url, apikey } = req.query;

      // Validasi API Key
      if (!global.apikey.includes(apikey)) {
        return res.status(403).json({ status: false, error: 'Apikey invalid' });
      }

      // Validasi URL
      if (!url) {
        return res.status(400).json({ status: false, error: 'Parameter url diperlukan' });
      }
      if (!url.includes("youtube.com") && !url.includes("youtu.be")) {
        return res.status(400).json({ status: false, error: 'Link YouTube tidak valid' });
      }

      console.log(`[YTMP3] Memproses audio dari URL: ${url}`);
      const result = await ytdl.ytmp3(url);

      if (!result.status || !result.download || !result.download.url) {
        throw new Error('Gagal mengunduh audio dari YouTube.');
      }
      
      res.status(200).json({
        status: true,
        creator: global.settings.creator || "Rikishopreal",
        result: {
          title: result.title,
          size: result.size,
          quality: result.quality, // Biasanya tidak relevan untuk MP3, tapi disertakan jika ada
          duration: result.duration,
          url: result.download.url
        }
      });

    } catch (e) {
      console.error("[YTMP3 Error]:", e);
      res.status(500).json({
        status: false,
        creator: global.settings.creator || "Rikishopreal",
        message: "Terjadi kesalahan pada server saat memproses audio.",
        error: e.message || e
      });
    }
  });
};

