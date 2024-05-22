const express          = require('express');
const app              = express();
const path             = require('path');
const nunjucks         = require('nunjucks');
const routes           = require('./routes');

app.use(express.json());
app.disable('etag');

nunjucks.configure('views', {
	autoescape: true,
	express: app
});

app.set('views', './views');
app.use('/static', express.static(path.resolve('static')));

app.use(routes);

app.all('*', (req, res) => {
	return res.status(404).send({
		message: '404 page not found'
	});
});

app.use((err, req, res, next) => {
    console.error(err);
    return res.status(500).send({
        message: '500 internal server error'
    });
});

(async () => {
	app.listen(5000, '0.0.0.0', () => console.log('listening on port 5000'));
})();