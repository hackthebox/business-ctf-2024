const express = require("express");
const { VM } = require("vm2");

const app = express();
const port = 3000;

app.use(express.json());

app.post("/run", (req, res) => {
    let { code } = req.body;
    
    if (typeof code !== "string") {
        return res.status(400).json({ error: "Code must be a string." });
    }

    const vm = new VM();

    try {
        let output = vm.run(code);
        res.json({ output });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.listen(port, () => {
    console.log(`Server running on http://127.0.0.1:${port}`);
});
