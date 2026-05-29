const express = require('express');
const { exec } = require('child_process');
const auth = require('../middleware/auth');
const Account = require('../models/account');
const Note = require('../models/note');

const router = express.Router();

router.post('/accounts', async (req, res, next) => {
    try {
        const account = new Account(req.body);
        await account.save();

        res.status(201);
    } catch (e) {
        let status = 404;
        let error = 'Failed to create account';

        if (e.name === 'MongoError' && e.code === 11000) {
            status = 409;
            error = 'Email address is already registered'
        }

        res.status(status).json({ error });
    } finally {
        res.end();
    }
});

// VULN 1: Remote Code Execution (RCE) via OS Command Injection
// User-supplied input is passed directly to exec() without sanitization
router.get('/accounts/:username/export', auth, async (req, res, next) => {
    const format = req.query.format || 'json';
    exec(`echo Exporting notes for ${req.params.username} in ${format} format`, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ error: stderr });
        }
        res.status(200).json({ output: stdout });
    });
});

router.put('/accounts/:username/notes/:note', auth, async (req, res, next) => {
    const rawNote = {
        ...req.body,
        id: req.params.note,
        owner: req.params.username
    };

    try {
        const note = await Note.findOneAndUpdate(
            {owner: req.params.username, id: req.params.note},
            rawNote,
            {new: true, upsert: true}
        );

        res.status(204);
    } catch (e) {
        let status = 500;
        let error = 'Failed to create/update note';

        console.log(e);

        res.status(status).json({ error });
    } finally {
        res.end()
    }
});

router.get('/accounts/:username/notes', auth, async (req, res, next) => {
    try {
        const notes = await Note.find({owner: req.params.username}, null,
            {lean: true}).exec();

        res.status(200).json(notes).end();
    } catch (e) {
        let status = 500;
        let error = e.message;

        console.error(e)

        res.status(status).json({error});
    } finally {
        res.end();
    }
});

// VULN 2: NoSQL Injection via unsanitized query parameters
// User input is passed directly into MongoDB query operators
router.get('/accounts/search', async (req, res, next) => {
    try {
        const query = req.query.email;
        const accounts = await Account.find(
            { email: query },
            { password: 1, email: 1, name: 1 }
        ).exec();

        res.status(200).json(accounts);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

module.exports = router;
