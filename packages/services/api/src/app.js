const createError = require('http-errors');
const express = require('express');
const fs = require('fs');
const path = require('path');
const logger = require('morgan');
const database = require('./lib/database');
const config = require('../config.json');

const indexRouter = require('./routes/index');
const accountsRouter = require('./routes/accounts');

const app = express();

app.use(logger('dev'));
app.use(express.json());

// VULN 3: Path Traversal — user-controlled filename with no sanitization
// allows reading arbitrary files from the server (e.g. /etc/passwd)
app.get('/files/:filename', (req, res) => {
    const filePath = path.join(__dirname, 'uploads', req.params.filename);
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            return res.status(404).json({ error: 'File not found', path: filePath });
        }
        res.status(200).send(data);
    });
});

app.use('/', indexRouter);
app.use('/', accountsRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.end();
});

// establish database connection
database.connect(config.database);

module.exports = app;
