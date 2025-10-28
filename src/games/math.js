const axios = require('axios');

module.exports = function(app) {
    const modes = { noob: [-3,3,-3,3,"+-",15e3,10], easy: [-10,10,-10,10,"*/+-",2e4,40], medium: [-40,40,-20,20,"*/+-",4e4,150], hard: [-100,100,-70,70,"*/+-",6e4,350], extreme: [-999999,999999,-999999,999999,"*/",99999,9999], impossible: [-99999999999,99999999999,-99999999999,999999999999,"*/",3e4,35e3], impossible2: [-999999999999999,999999999999999,-999,999,"/",3e4,5e4], impossible3: [-999999999999999999,999999999999999999,-999999999999999999,999999999999999999,"*/",1e5,1e5], impossible4: [-999999999999999999999,999999999999999999999,-999999999999999999999,999999999999999999999,"*/",5e5,5e5], impossible5: [-999999999999999999999999,999999999999999999999999,-999999999999999999999999,999999999999999999999999,"*/",1e6,1e6] };
    const operators = { "+": "+", "-": "-", "*": "×", "/": "÷" };
    function randomInt(from, to) { if (from > to) [from, to] = [to, from]; from = Math.floor(from); to = Math.floor(to); return Math.floor((to - from) * Math.random() + from); }
    function pickRandom(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

    async function generateMathProblem(level) {
        try {
            const [a1, a2, b1, b2, ops, time, bonus] = modes[level];
            let a = randomInt(a1, a2); let b = randomInt(b1, b2); const op = pickRandom([...ops]); let result;
            if (op === "/") { while (b === 0) { b = randomInt(b1, b2); } a = a - (a % b); if (a === 0 && b !== 0) { a = b * randomInt(1,5); } else if (a === 0 && b === 0) { b = randomInt(1, 10); a = b * randomInt(1, 5); } result = a / b; }
            else { result = new Function(`return ${a} ${op === '*' ? '*' : op} ${b < 0 ? `(${b})` : b}`)(); }
            if (typeof result !== 'number' || isNaN(result) || !isFinite(result)) { throw new Error('Hasil perhitungan matematika tidak valid'); }
            return { str: `${a} ${operators[op]} ${b}`, mode: level, time: time, bonus: bonus, result: result };
        } catch (error) { console.error("Math generation error:", error.message); throw error; }
    }

    const handleMathRequest = async (req, res) => {
        try {
            const { apikey, level } = req.method === 'GET' ? req.query : req.body;

            // 1. Validasi API Key
            if (!global.apikey.includes(apikey)) { return res.json({ status: false, error: 'Apikey invalid' }); }

            // 2. Validasi Level
            const validLevels = Object.keys(modes);
            if (level && typeof level !== "string") { return res.status(400).json({ status: false, error: "Parameter level harus string" }); } // Error 400 untuk param
            const chosenLevel = level && validLevels.includes(level) ? level : pickRandom(validLevels);

            // 3. Generate soal
            const result = await generateMathProblem(chosenLevel);

            // 4. Kirim Respons Sukses
            res.json({ status: true, result: result });

        } catch (error) {
            // 5. Tangani Error
            console.error(`[maths ${req.method}] Error:`, error.message);
            res.status(500).send(`Error: ${error.message}`);
        }
    };

    // --- PATH DIUBAH DI SINI ---
    app.get('/games/maths', handleMathRequest);
    app.post('/games/maths', handleMathRequest);
    // --- AKHIR PERUBAHAN PATH ---
};
