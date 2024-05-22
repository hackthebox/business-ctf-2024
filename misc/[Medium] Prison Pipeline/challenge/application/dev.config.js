module.exports = {
    apps : [
        {
          name: "prison-pipeline",
          cwd: '/app/',
          script: "index.js",
          watch: ["."],
          watch_delay: 1000,
          ignore_watch : ["node_modules", "prisoner-repository"],
          env: {
              "NODE_ENV": "development"
          }
        }
    ]
}