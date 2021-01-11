// Express
const express = require('express');
const app = express();

// Mongoose
const { mongoose } = require('./db/mongoose');

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

// Listen
app.listen(9800, () => {
    console.log("Server is listening on port 9500");
});
