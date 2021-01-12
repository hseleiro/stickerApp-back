// Express
const express = require('express');
const app = express();

// Mongoose
const { mongoose } = require('./db/mongoose');

// Mongoose models
const { User } = require('./models/index');

// Cors
const cors = require('cors');

// Body Parse
const bodyParser = require('body-parser');

// Morgan
const morgan = require('morgan');

// JWT
const jwt = require('jsonwebtoken');

/* MIDDLEWARE  */

// Body Parser
app.use(bodyParser.json());
// Cors
app.use(cors({origin: 'http://localhost:4200'}));
app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS, PUT, PATCH, DELETE");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, x-access-token, x-refresh-token, _id");

    res.header(
        'Access-Control-Expose-Headers',
        'x-access-token, x-refresh-token'
    );

    next();
});
// Morgan
app.use(morgan('dev'));

// Verify if the request as a valid JWT
let authenticate = (req, res, next) => {

    let token = req.header('x-access-token');
    jwt.verify(token, User.getJWTSecret(), (err, decoded) => {
        if(err) {
            // jwt is invalid - DO NOT AUTHENTICATE
            res.status(401).send(err);
        } else {
            // jwt is valid
            req.user_id = decoded.id;
            next();
        }
    })
}

// Verify Refresh Token Middleware (Which will be verifying the session)
let verifySession = (req, res, next) => {
    // Grab the refresh token from the request header
    let refreshToken = req.header('x-refresh-token');
    // Grab id from the request header
    let _id = req.header('_id')
    // Find user
    User.findByIdAndToken(_id, refreshToken).then((user) => {
        if(!user) {
            return Promise.reject({
                'error': 'User not found. Make sure that the refresh token and user id are correct'
            })
        }

        // if the code reaches here - the user was found
        // therefore the refresh token exists in the database - but we still have to check if it has expired or not

        req.user_id = user._id;
        req.userObject = user;
        req.refreshToken = refreshToken;

        let isSessionValid = false;

        user.sessions.forEach((session) => {
            if(session.token === refreshToken) {
                // Check if the session has expired
                if (User.hasRefreshTokenExpired(session.expiresAt) === false) {
                    // refresh token has not expired
                    isSessionValid = true;
                }
            }
        })

        if(isSessionValid) {
            // the session is VALID - call next() to continue with processing this web request
            next();
        } else {
            return Promise.reject({
                'error': 'Refresh token has expired or the session is invalid'
            })
        }

    }).catch((e) => {
        res.status(401).send(e);
    })

};

/**
 * POST /users
 * Purpose: Sign up
 */

app.post('/users/sign-up', (req, res) => {
    let body = req.body;
    let newUser = new User(body);

    newUser.save().then(() => {
        return newUser.createSession();
    }).then((refreshToken) => {
        // Session created successfully - refreshToken returned.
        // now we generate an access auth token for the user
        return newUser.generateAccessAuthToken().then((accessToken) => {
            return { accessToken, refreshToken }
        });
    }).then((authTokens) => {
        res
            .header('x-refresh-token', authTokens.refreshToken)
            .header('x-access-token', authTokens.accessToken)
            .send(newUser)
    }).catch((e) => {
        console.log(e);
        res.status(400).send(e);
    })
});

/**
 * POST /users
 * Purpose: Sign in
 */

app.post('/users/sign-in', (req, res) => {
    let email = req.body.email;
    let password = req.body.password;

    User.findByCredentials(email, password).then((user) => {
        return user.createSession().then((refreshToken) => {
            // Session created successfully - refreshToken returned.
            // now we generate an access auth token for the user

            return user.generateAccessAuthToken().then((accessToken) => {
                return { accessToken, refreshToken }
            });
        }).then((authTokens) => {
            // Now we construct and send the response to the user with their auth tokens in the header and the user object in the body
            res
                .header('x-refresh-token', authTokens.refreshToken)
                .header('x-access-token', authTokens.accessToken)
                .send(user);
        })

    }).catch((e) => {
        res.status(400).send(e);
    });

});

app.get('/users/me/access-token', verifySession, (req, res) => {
    req.userObject.generateAccessAuthToken().then((accessToken) => {
        res.header('x-access-token', accessToken).send({ accessToken });
    }).catch((e) => {
        res.status(400).send(e);
    });
});

// Listen
app.listen(9600, () => {
    console.log("Server is listening on port 9600");
});
