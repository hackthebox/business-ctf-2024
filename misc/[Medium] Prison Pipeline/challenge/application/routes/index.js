const express         = require('express');
const router          = express.Router({caseSensitive: true});
const prisonerDB      = require('prisoner-db');

const db = new prisonerDB('/app/prisoner-repository');

const response = data => ({ message: data });

router.get('/', (req, res) => {
	return res.render('index.html');
});

router.get('/api/prisoners', async (req, res) => {
	let prisoners = db.getPrisoners();

    return res.json(prisoners);
});

router.get('/api/prisoners/:id', async (req, res) => {
    const { id } = req.params;

	let prisoner = db.getPrisoner(id);

    return res.json(prisoner);
});

router.post('/api/prisoners/import', async (req, res, next) => {
	const { url } = req.body;
    if (!url) {
        return res.status(400).json(response('Missing URL parameter'));
    };

    try {
        let prisoner_id = await db.importPrisoner(url);
        return res.json({
            'message': 'Prisoner data imported successfully',
            'prisoner_id': prisoner_id
        });
    }
	catch(e) {
	    console.error(e);
        return res.status(500).json(response('Failed to import prisoner data'));
	}
});


module.exports = router