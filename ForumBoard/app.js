const sqlite3 = require('sqlite3');
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const session = require('express-session');

const app = express();

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: true }))

app.use(session({
    secret: 'TotallyASecret',
    resave: false,
    saveUninitialized: false
}))

// here is where we define the database

const db = new sqlite3.Database('database/data.db', (err) => {
    if (err) {
        console.log(err);
    } else {
        console.log('database is connected');
    }
});

function isAuthenticated(req, res, next) {
    if (req.session.user) next()
    else res.redirect('/login')
};

app.get('/', (req, res) => {
    res.render('login');
});

app.get('/forum', (req, res) => {
    console.log('login page');
    res.render('forum', { user: req.session.user });
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
                //create a new salt
                const salt = crypto.randomBytes(16).toString("hex")

                //use the salt to 'hash' the password
                crypto.pbkdf2(req.body.pass, salt, 1000, 64, 'sha512', (err, derivedKey) => {
                    if (err) {
                        res.send('Error hashing password: \n' + err)
                    } else {
                        const hashPassword = derivedKey.toString('hex')

                        db.run('INSERT INTO users (username, password, salt) VALUES (?, ?, ?);', [req.body.user, hashPassword, salt], (err) => {
                            if (err) {
                                res.send('Database error:\n' + err)
                            } else {
                            res.send("Created new user")
                            }
                        })
                    }
                })

                
            }
            else if (row) {
                //compare storage password with provided password
                crypto.pbkdf2(req.body.pass, row.salt, 1000, 64, 'sha512', (err, derivedKey) => {
                    if (err) {
                        res.send('Error hashing password: \n' + err)
                    } else {
                        const hashPassword = derivedKey.toString('hex')

                        if (row.password === hashPassword) {
                            req.session.user = req.body.user;
                            res.redirect('/profile')
                        } else {
                            res.send('Incorrect')
                        }
                    }
                })
            }
        })
    } else {
        res.send("You need a username and password");
    }
})

app.get('/profile', isAuthenticated, (req, res) => {
    res.render('profile.ejs', { user: req.session.user })
})



app.listen(3000, () => {
    console.log(`Server started on port 3000`);
});