const ipWrapper = require("ip-wrapper");
const express = require("express");

const app = express();
app.use(express.json());

const validateInput = (req, res, next) => {
    const { interface } = req.body;

    if (
        !interface || 
        typeof interface !== "string" || 
        interface.trim() === "" || 
        interface.includes(" ")
    ) {
        return res.status(400).json({message: "A valid interface is required"});
    }

    next();
}

app.post("/getAddresses", async (req, res) => {
    try {
        const addr = await ipWrapper.addr.show();
        res.json(addr);
    } catch (err) {
        res.status(401).json({message: "Error getting addresses"});
    }
});

app.post("/flushInterface", validateInput, async (req, res) => {
    const { interface } = req.body;

    try {
        const addr = await ipWrapper.addr.flush(interface);
        res.json(addr);
    } catch (err) {
        res.status(401).json({message: "Error flushing interface"});
    }
});

app.listen(5000, () => {
    console.log("Network utils API is up on :5000");
});