const yts = require('yt-search');
const ytdl = require('@vreden/youtube_scraper');
const axios = require('axios');

/**
 * Membersihkan judul lagu untuk pencarian lirik yang lebih akurat.
 * @param {string} title - Judul asli dari video YouTube.
 * @returns {string} Judul yang sudah dibersihkan.
 */
function cleanTitle(title) {
    let cleaned = title;
    cleaned = cleaned.replace(/\s*\[.*?\]/g, ''); // Hapus kurung siku []
    cleaned = cleaned.replace(/\s*\(.*?\)/g, ''); // Hapus kurung biasa ()
    if (cleaned.includes(' - ')) {
        cleaned = cleaned.split(' - ')[1]; // Ambil bagian setelah "Artis - "
    }
    const keywords = ['official', 'music', 'lyric', 'video', 'audio', 'mv', '#'];
    const regex = new RegExp(keywords.join('|'), 'ig');
    cleaned = cleaned.replace(regex, '');
    return cleaned.trim();
}

/**
 * Fungsi utama untuk mencari video, mendapatkan link audio, dan lirik.
 * @param {string} query - Judul lagu yang dicari.
 * @returns {Promise<object>} Objek berisi detail video, link audio, dan lirik.
 */
async function playScraper(query) {
    try {
        const search = await yts(query);
        const video = search.videos[0];
        if (!video) {
            throw new Error("Lagu tidak ditemukan di YouTube.");
        }

        const audioInfo = await ytdl.ytmp3(video.url);
        if (!audioInfo.status || !audioInfo.download || !audioInfo.download.url) {
            throw new Error("Gagal mendapatkan link unduhan audio.");
        }
        
        const audioUrl = audioInfo.download.url;

        let lyricsResult = {
            lyrics: "Lirik tidak ditemukan.",
            artist: video.author.name // Default artist dari YouTube
        };

        try {
            const cleanedTitle = cleanTitle(video.title);
            // Menggunakan API lirik publik
            const lyricsResponse = await axios.get(`https://some-random-api.com/lyrics?title=${encodeURIComponent(cleanedTitle)}`);
            const lyricData = lyricsResponse.data;

            if (lyricData && !lyricData.error && lyricData.lyrics) {
                lyricsResult.lyrics = lyricData.lyrics;
                lyricsResult.artist = lyricData.author || video.author.name;
            }
        } catch (lyricError) {
            console.warn(`Peringatan: Gagal mengambil lirik untuk "${video.title}". Pesan: ${lyricError.message}`);
            // Gagal mengambil lirik tidak menghentikan proses, hanya menampilkan pesan default.
        }

        return {
            video_details: {
                title: video.title,
                url: video.url,
                duration: video.timestamp,
                thumbnail: video.thumbnail,
                author: video.author.name
            },
            audio_download_url: audioUrl,
            lyrics: lyricsResult
        };

    } catch (error) {
        console.error("Error di dalam playScraper:", error.message);
        throw error; // Melempar error ke route handler
    }
}

// Mengekspor fungsi untuk diintegrasikan dengan Express
module.exports = function (app) {
    app.get('/download/play', async (req, res) => {
        try {
            const { q, apikey } = req.query;

            // Validasi API Key dan parameter
            if (!global.apikey.includes(apikey)) {
                return res.status(403).json({ status: false, error: 'Apikey invalid' });
            }
            if (!q) {
                return res.status(400).json({ status: false, error: 'Parameter q (query) diperlukan' });
            }

            // Memanggil scraper
            const results = await playScraper(q);
            
            // Mengirim hasil
            res.status(200).json({
                status: true,
                result: results
            });
        } catch (error) {
            // Menangani error
            res.status(500).json({
                status: false,
                message: "Terjadi kesalahan pada server saat memproses permintaan.",
                error: error.message
            });
        }
    });
};

