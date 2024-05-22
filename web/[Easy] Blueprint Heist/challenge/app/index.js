const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const { renderError, generateError } = require("./controllers/errorController");
const publicRoutes = require("./routes/public")
const internalRoutes = require("./routes/internal")

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.set("view engine", "ejs");
app.use('/static', express.static(path.join(__dirname, 'static')));

app.use(internalRoutes)
app.use(publicRoutes)

app.use((res, req, next) => {
  const err = generateError(404, "Not Found")
  return next(err);
});

app.use((err, req, res, next) => {
  renderError(err, req, res);
});

const port = 1337;
app.listen(port, '0.0.0.0', () => {
  console.log(`Server is running on http://localhost:${port}`);
});
