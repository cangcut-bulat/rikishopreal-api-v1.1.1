const ytdl = require('@vreden/youtube_scraper');

module.exports = function (app) {
  app.get('/download/ytmp4', async (req, res) => {
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

      console.log(`[YTMP4] Memproses video dari URL: ${url}`);
      const result = await ytdl.ytmp4(url);

      if (!result.status || !result.download || !result.download.url) {
        throw new Error('Gagal mengunduh video dari YouTube.');
      }
      
      res.status(200).json({
        status: true,
        creator: global.settings.creator || "Rikishopreal",
        result: {
          title: result.title,
          size: result.size,
          quality: result.quality,
          duration: result.duration,
          url: result.download.url
        }
      });

    } catch (e) {
      console.error("[YTMP4 Error]:", e);
      res.status(500).json({
        status: false,
        creator: global.settings.creator || "Rikishopreal",
        message: "Terjadi kesalahan pada server saat memproses video.",
        error: e.message || e
      });
    }
  });
};

