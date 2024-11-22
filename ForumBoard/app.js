const sqlite3 = require('sqlite3');
const express = require('express');
const app = express();
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const http = require("http");
const { log } = require('console');

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: 'TotallyASecret',
    resave: false,
    saveUninitialized: false
}));

const db = new sqlite3.Database('database/data.db', (err) => {
    if (err) {
        console.log(err);
    } else {
        console.log('database is connected');
    }
});

function isAuthenticated(req, res, next) {
    if (req.session.user) next();
    else res.redirect('/login');
}

app.get('/', (req, res) => {
    res.render('login');
});

app.get('/forum', isAuthenticated, (req, res) => {
    console.log('forum page');

    db.all('SELECT title FROM forum;', (err, rows) => {
        if (err) {
            console.error(err);
            res.send("There was an error:\n" + err);
        } else {
            res.render('forum', { user: req.session.user, forums: rows });
        }
    });
});

app.post('/login', (req, res) => {
    console.log(req.body.user);
    console.log(req.body.pass);
    if (req.body.user && req.body.pass) {
        db.get('SELECT * FROM users WHERE username=?;', req.body.user, (err, row) => {
            if (err) {
                console.error(err);
                res.send("There was an error:\n" + err);
            } else if (!row) {
                const salt = crypto.randomBytes(16).toString("hex");
                crypto.pbkdf2(req.body.pass, salt, 1000, 64, 'sha512', (err, derivedKey) => {
                    if (err) {
                        res.send('Error hashing password: \n' + err);
                    } else {
                        const hashPassword = derivedKey.toString('hex');
                        db.run('INSERT INTO users (username, password, salt) VALUES (?, ?, ?);', [req.body.user, hashPassword, salt], (err) => {
                            if (err) {
                                res.send('Database error:\n' + err);
                            } else {
                                res.send("Created new user");
                            }
                        });
                    }
                });
            } else if (row) {
                crypto.pbkdf2(req.body.pass, row.salt, 1000, 64, 'sha512', (err, derivedKey) => {
                    if (err) {
                        res.send('Error hashing password: \n' + err);
                    } else {
                        const hashPassword = derivedKey.toString('hex');
                        if (row.password === hashPassword) {
                            req.session.user = req.body.user;
                            res.redirect('/profile');
                        } else {
                            res.send('Incorrect');
                        }
                    }
                });
            }
        });
    } else {
        res.send("You need a username and password");
    }
});

app.get('/profile', isAuthenticated, (req, res) => {
    res.render('profile.ejs', { user: req.session.user });
});

app.get('/chat/:forumName', isAuthenticated, (req, res) => {
    const forumName = req.params.forumName;
    console.log('chat page for forum:', forumName);
    res.render('chat', { user: req.session.user, forumName: forumName });
});

app.post('/forum', (req, res) => {
    console.log(req.body.forumName);
    console.log(req.session.user);

    const user = req.session.user;
    const forumName = req.body.forumName;

    db.run('INSERT INTO forum (creator, title) VALUES (?, ?);', [user, forumName], (err) => {
        if (err) {
            res.send('Database error:\n' + err);
        } else {
            res.redirect('/forum');
        }
    });
});

app.post('/chat/:forumName', (req, res) => {

    db.run('INSERT INTO messages (user, content, date) VALUES (?, ?, ?);', [user, forumName, date], (err) => {
        if (err) {
            res.send('Database error:\n' + err);
        } else {
            res.redirect('/forum');
        }
    });
});

app.listen(3000, () => {
    console.log(`Server is running on http://localhost:3000`);
});