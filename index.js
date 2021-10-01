const express = require('express');
const jwt = require('express-jwt');
const jwks = require('jwks-rsa');
const axios = require('axios');
require('dotenv').config();

const app = express();

const { 
    CLIENT_ID, 
    CLIENT_SECRET,
    AUDIENCE, 
    API_USER, 
    API_PSWD,
    PORT
} = process.env;
const port = PORT || 5001;

app.use(express.json());

function authenticationMiddleware(req, res, next) {
    const { username, password } = req.body;
    if (username !== API_USER && password !== API_PSWD)
        res.sendStatus(403);
    next();
}

const jwtCheck = jwt({
    secret: jwks.expressJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: 'https://devjpsmith.auth0.com/.well-known/jwks.json'
  }),
  audience: AUDIENCE,
  issuer: 'https://devjpsmith.auth0.com/',
  algorithms: ['RS256']
});

app.post('/token', authenticationMiddleware, (req,res) => {
    axios({
        method: 'POST',
        url: 'https://devjpsmith.auth0.com/oauth/token',
        data: {
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            audience:AUDIENCE,
            grant_type:'client_credentials'
        }
    })
        .then(response => {
            res.status(200).send(response.data.access_token)
        })
        .catch(() => res.sendStatus(503));
})

app.get('/public', (_, res) => {
    res.status(200).send('Hello public');
});

app.get('/private', jwtCheck, (_, res) => {
    res.status(200).send('Hello private');
});

app.get('*', (_, res) => {
    res.sendStatus(404);
});


app.listen(port, () => console.log(`API listening on port ${port}`));