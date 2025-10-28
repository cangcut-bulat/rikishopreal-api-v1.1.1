const axios = require('axios');

module.exports = function(app) {
    const subjects = {
      bindo: "https://gist.githubusercontent.com/siputzx/298d2d3bd5901494537b9848e35dab9f/raw/25f5dcfef0d97141c555c2bbb94fe1f3d1f76cb3/bindo.json",
      tik: "https://gist.githubusercontent.com/siputzx/298d2d3bd5901494537b9848e35dab9f/raw/25f5dcfef0d97141c555c2bbb94fe1f3d1f76cb3/tik.json",
      pkn: "https://gist.githubusercontent.com/siputzx/298d2d3bd5901494537b9848e35dab9f/raw/25f5dcfef0d97141c555c2bbb94fe1f3d1f76cb3/pkn.json",
      bing: "https://gist.githubusercontent.com/siputzx/298d2d3bd5901494537b9848e35dab9f/raw/25f5dcfef0d97141c555c2bbb94fe1f3d1f76cb3/bing.json",
      penjas: "https://gist.githubusercontent.com/siputzx/298d2d3bd5901494537b9848e35dab9f/raw/25f5dcfef0d97141c555c2bbb94fe1f3d1f76cb3/penjas.json",
      pai: "https://gist.githubusercontent.com/siputzx/298d2d3bd5901494537b9848e35dab9f/raw/25f5dcfef0d97141c555c2bbb94fe1f3d1f76cb3/pai.json",
      matematika: "https://gist.githubusercontent.com/siputzx/298d2d3bd5901494537b9848e35dab9f/raw/25f5dcfef0d97141c555c2bbb94fe1f3d1f76cb3/matematika.json",
      jawa: "https://gist.githubusercontent.com/siputzx/298d2d3bd5901494537b9848e35dab9f/raw/25f5dcfef0d97141c555c2bbb94fe1f3d1f76cb3/jawa.json",
      ips: "https://gist.githubusercontent.com/siputzx/298d2d3bd5901494537b9848e35dab9f/raw/25f5dcfef0d97141c555c2bbb94fe1f3d1f76cb3/ips.json",
      ipa: "https://gist.githubusercontent.com/siputzx/298d2d3bd5901494537b9848e35dab9f/raw/25f5dcfef0d97141c555c2bbb94fe1f3d1f76cb3/ipa.json",
    };
    function shuffleArray(array) { const shuffled = [...array]; for (let i = shuffled.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]]; } return shuffled; }
    function getRandomQuestions(questions, count) { const shuffled = shuffleArray(questions); return shuffled.slice(0, count); }

    async function scrapeQuiz(matapelajaran, jumlahsoal) {
      try {
        if (!subjects[matapelajaran]) { throw new Error(`Mata pelajaran '${matapelajaran}' tidak tersedia`); }
        let numQuestions = Math.max(5, Math.min(10, parseInt(jumlahsoal) || 5));
        const response = await axios.get(subjects[matapelajaran], { timeout: 30000, headers: { "User-Agent": "Mozilla/5.0" } });
        const allQuestions = response.data;
        if (!Array.isArray(allQuestions) || allQuestions.length === 0) { throw new Error(`Data soal '${matapelajaran}' tidak valid/kosong`); }
        if (allQuestions.length < numQuestions) { console.warn(`Soal tersedia (${allQuestions.length}) < diminta (${numQuestions}). Menggunakan ${allQuestions.length}.`); numQuestions = allQuestions.length; }
        const selectedQuestions = getRandomQuestions(allQuestions, numQuestions);
        const transformedQuestions = selectedQuestions.map((q) => {
           const correctAnswer = q.jawaban_benar?.teks; if (!correctAnswer || !Array.isArray(q.semua_jawaban)) { console.warn('Skip invalid question:', q.pertanyaan); return null; }
           const answerValues = q.semua_jawaban.map(opt => opt[Object.keys(opt)[0]]).filter(val => val != null); if (answerValues.length === 0) { console.warn('Skip no valid answers:', q.pertanyaan); return null; }
          const shuffledAnswers = shuffleArray(answerValues); const keys = ["a","b","c","d","e","f","g","h","i","j"]; const availableKeys = keys.slice(0, shuffledAnswers.length); const newAnswerOptions = shuffledAnswers.map((v, i) => ({ [availableKeys[i]]: v }));
          let correctOption = null; for (const option of newAnswerOptions) { const key = Object.keys(option)[0]; if (option[key] === correctAnswer) { correctOption = key; break; } } if (!correctOption) { console.warn('Correct answer not found:', q.pertanyaan); correctOption = 'a'; }
          return { pertanyaan: q.pertanyaan, semua_jawaban: newAnswerOptions, jawaban_benar: correctOption };
        }).filter(q => q !== null);
        if (transformedQuestions.length === 0) { throw new Error('Gagal proses, tidak ada soal valid tersisa.'); }
        return { matapelajaran, jumlah_soal: transformedQuestions.length, soal: transformedQuestions };
      } catch (error) { console.error("API Error (scrapeQuiz):", error.message); throw error; }
    }

    const handleCerdasCermatRequest = async (req, res) => {
        try {
            const { apikey, matapelajaran, jumlahsoal } = req.method === 'GET' ? req.query : req.body;

            // 1. Validasi API Key
            if (!global.apikey.includes(apikey)) { return res.json({ status: false, error: 'Apikey invalid' }); }

            // 2. Validasi Matapelajaran
            if (!matapelajaran) { return res.status(400).json({ status: false, error: "Parameter matapelajaran wajib diisi", available_subjects: Object.keys(subjects) }); }
            if (typeof matapelajaran !== "string" || !subjects[matapelajaran.trim()]) { return res.status(400).json({ status: false, error: `Mata pelajaran tidak valid. Pilihan: ${Object.keys(subjects).join(", ")}` }); }

            // 3. Validasi Jumlah Soal
            let numSoalValidated = 5;
            if (jumlahsoal != null) { const parsedJumlah = parseInt(jumlahsoal); if (isNaN(parsedJumlah) || parsedJumlah < 5 || parsedJumlah > 10) { return res.status(400).json({ status: false, error: "Parameter jumlahsoal harus angka antara 5 dan 10" }); } numSoalValidated = parsedJumlah; }

            // 4. Panggil helper
            const result = await scrapeQuiz(matapelajaran.trim(), numSoalValidated);

            // 5. Kirim Respons Sukses
            res.json({ status: true, result: result });

        } catch (error) {
            // 6. Tangani Error
            console.error(`[cc-sd ${req.method}] Error:`, error.message);
            res.status(500).send(`Error: ${error.message}`);
        }
    };

    // --- PATH DIUBAH DI SINI ---
    app.get('/games/cc-sd', handleCerdasCermatRequest);
    app.post('/games/cc-sd', handleCerdasCermatRequest);
    // --- AKHIR PERUBAHAN PATH ---
};
