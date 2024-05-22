import { Client, GatewayIntentBits, REST, Routes, EmbedBuilder } from "discord.js";
import axios from "axios";

const token = process.env.BOT_TOKEN;
const clientId = process.env.CLIENT_ID;

const evaluateCode = async (code) => {
    try {
        const response = await axios.post("http://api:3000/run", { code });
        return JSON.stringify(response.data.output);
    } catch (error) {
        return error.message;
    }
}

const getRandomPrice = () => Math.floor(Math.random() * (12 - 5 + 1)) + 5;

let products = [
    { id: "PROD001", name: "Blamco Brand Mac and Cheese", description: "A cheesy delight for those in the wasteland.", price: getRandomPrice(), image: "https://images.fallout.wiki/thumb/f/fb/Fallout4_Blamco_brand_mac_and_cheese.png/540px-Fallout4_Blamco_brand_mac_and_cheese.png" },
    { id: "PROD002", name: "InstaMash", description: "Instant mashed potatoes.", price: getRandomPrice(), image: "https://images.fallout.wiki/thumb/c/ce/Fallout4_InstaMash.png/540px-Fallout4_InstaMash.png" },
    { id: "PROD003", name: "Sugar Bombs", description: "Pre-war breakfast cereal.", price: getRandomPrice(), image: "https://images.fallout.wiki/thumb/d/d7/Fallout4_Sugar_Bombs.png/361px-Fallout4_Sugar_Bombs.png" },
    { id: "PROD004", name: "Salisbury Steak", description: "Tasty, preserved Salisbury steak.", price: getRandomPrice(), image: "https://images.fallout.wiki/thumb/0/0f/Fallout4_Salisbury_Steak.png/540px-Fallout4_Salisbury_Steak.png" },
    { id: "PROD005", name: "Potato Crisps", description: "Crispy and salty potato chips.", price: getRandomPrice(), image: "https://images.fallout.wiki/thumb/a/ab/Fallout4_Potato_Crisps.png/242px-Fallout4_Potato_Crisps.png" },
    { id: "PROD006", name: "Pork n' Beans", description: "A can of beans with bits of pork.", price: getRandomPrice(), image: "https://images.fallout.wiki/thumb/2/24/Fallout4_Pork_n%27_Beans.png/376px-Fallout4_Pork_n%27_Beans.png" },
    { id: "PROD007", name: "Fancy Lads Snack Cakes", description: "Pre-war snack cakes.", price: getRandomPrice(), image: "https://images.fallout.wiki/thumb/5/57/Fallout4_Fancy_lads_snack_cakes.png/368px-Fallout4_Fancy_lads_snack_cakes.png" },
    { id: "PROD008", name: "Dandy Boy Apples", description: "Preserved pre-war apples.", price: getRandomPrice(), image: "https://images.fallout.wiki/thumb/0/05/Fo4_Dandy_Boy_Apples.png/540px-Fo4_Dandy_Boy_Apples.png" },
    { id: "PROD009", name: "Cram", description: "Canned meat product.", price: getRandomPrice(), image: "https://images.fallout.wiki/thumb/7/72/Fallout4_Cram.png/540px-Fallout4_Cram.png" },
    { id: "PROD010", name: "Canned Dog Food", description: "Dog food, but you can eat it too.", price: getRandomPrice(), image: "https://images.fallout.wiki/thumb/b/b7/Canned_dog_food.png/371px-Canned_dog_food.png" },
    { id: "PROD011", name: "Yum Yum Deviled Eggs", description: "Canned deviled eggs.", price: getRandomPrice(), image: "https://images.fallout.wiki/6/68/FO76_Yum_yum_deviled_eggs.png" },
    { id: "PROD012", name: "Purified Water", description: "Clean, safe water.", price: 10, image: "https://images.fallout.wiki/thumb/4/4d/Fo4_purified_water.png/308px-Fo4_purified_water.png" },
    { id: "PROD013", name: "Whiskey", description: "Strong alcoholic drink.", price: 8, image: "https://images.fallout.wiki/thumb/3/3d/Fo4_Whiskey.png/331px-Fo4_Whiskey.png" },
    { id: "PROD014", name: "Nuka-Cola", description: "The classic post-apocalyptic refreshment.", price: 20, image: "https://images.fallout.wiki/thumb/1/10/Fallout4_Nuka_Cola.png/300px-Fallout4_Nuka_Cola.png" },
    { id: "PROD015", name: "Nuka-Cola Quantum", description: "A special variant of Nuka-Cola that glows.", price: 100, image: "https://images.fallout.wiki/thumb/e/e6/Fallout4_Nuka_Cola_Quantum.png/300px-Fallout4_Nuka_Cola_Quantum.png" }
];

const carts = {};

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

client.on("ready", () => {
    console.log(`Logged in as ${client.user.tag}!`);
});

const commands = [
    {
        name: "listproducts",
        description: "Lists all available products in the vending machine"
    },
    {
        name: "addtocart",
        description: "Adds a product to your cart",
        options: [{
            name: "id",
            type: 3,
            description: "Product ID",
            required: true
        }, {
            name: "quantity",
            type: 4,
            description: "Quantity",
            required: true
        }]
    },
    {
        name: "viewcart",
        description: "View the items in your cart"
    },
    {
        name: "checkout",
        description: "Check out and calculate the total price",
        options: [{
            name: "discount",
            type: 3,
            description: "Discount code",
            required: false
        }]
    }
];

const rest = new REST({ version: "10" }).setToken(token);

(async () => {
    try {
        console.log("Started refreshing application (/) commands globally.");

        await rest.put(
            Routes.applicationCommands(clientId),
            { body: commands },
        );

        console.log("Successfully reloaded application (/) commands globally.");
    } catch (error) {
        console.error(error);
    }
})();

client.on("interactionCreate", async interaction => {
    if (!interaction.isChatInputCommand()) return;

    const { commandName } = interaction;

    if (commandName === "listproducts") {
        const embeds = products.map(product => {
            return new EmbedBuilder()
                .setColor(0x0099ff)
                .setTitle(product.name)
                .setDescription(product.description)
                .addFields(
                    { name: "ID", value: product.id },
                    { name: "Price", value: `${product.price} caps` }
                )
                .setImage(product.image);
        });

        const chunks = [];
        for (let i = 0; i < embeds.length; i += 10) {
            chunks.push(embeds.slice(i, i + 10));
        }

        for (const chunk of chunks) {
            await interaction.channel.send({ embeds: chunk });
        }
        await interaction.reply({ content: "Here are the available products:", ephemeral: true });
    }

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

    if (commandName === "viewcart") {
        const cart = carts[interaction.user.id] || [];
        if (cart.length === 0) {
            await interaction.reply("Your cart is empty.");
            return;
        }

        const embed = new EmbedBuilder()
            .setColor(0x0099ff)
            .setTitle("Your Cart")
            .setDescription("Here are the items in your cart:");

        cart.forEach(item => {
            embed.addFields({ name: item.product.name, value: `Quantity: ${item.quantity}, Price: ${item.product.price} caps each` });
        });

        await interaction.reply({ embeds: [embed] });
    }

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
});

client.login(token);
