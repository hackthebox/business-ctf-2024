module.exports = {
    apps : [
        {
            name: "prison-pipeline",
            cwd: '/app/',
            script: "index.js",
            watch: false,
            pmx: false,
            env: {
                "NODE_ENV": "production"
            }
        }
    ]
}