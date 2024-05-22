const express = require('express');
const path = require('path');
const util = require('util');
const exec = util.promisify(require('child_process').exec);

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.get('/', async (req, res) => {
    res.sendFile(path.join(__dirname, '/public/html/index.html'));
})

app.post('/server_status', async (req, res) => {
    const { choice,ㅤ} = req.body;
    const integerChoice = +choice;
    
    if (isNaN(integerChoice)) {
        return res.status(400).send('Invalid choice: must be a number');
    }

    const commands = [
        'free -m',
        'uptime',
        'iostat',
        'mpstat',
        'netstat',
        'ps aux',ㅤ
    ];

    if (integerChoice < 0 || integerChoice >= commands.length) {
        return res.status(400).send('Invalid choice: out of bounds');
    }

    exec(commands[integerChoice], (error, stdout) => {
        if (error) {
            return res.status(500).send('Error executing command');
        }

        res.status(200).send(stdout);
    });
});

app.listen(1337);
