const express = require("express");
const session = require('express-session');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const { Issuer } = require('openid-client')

dotenv.config();

const app = express();

app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(bodyParser.json());

app.use(session({
    secret: 'myultrasecret',
    resave: true,
    saveUninitialized: true
}));

function isAuthenticated(req, res, next) {
    if (req.session.user) {
        console.log('user is present')
        next();
    } else {
        res.redirect('/login');
    }
}

const keycloakIssuer = new Issuer({
    issuer: process.env.ISSUER,
    authorization_endpoint: process.env.AUTHORIZATION_ENDPOINT,
    token_endpoint: process.env.TOKEN_ENDPOINT,
    userinfo_endpoint: process.env.USERINFO_ENDPOINT,
    jwks_uri: process.env.JWKS_URI,
    end_session_endpoint: process.env.END_SESSION_ENDPOINT,
})

const client = new keycloakIssuer.Client({
    client_id: process.env.CLIENT_ID,
    client_secret: process.env.CLIENT_SECRET,
    redirect_uris: ['http://localhost:3000/oauth/callback'],
    response_types: ['code']
});

app.get('/', isAuthenticated, function (req, res) {
    return res.status(200).send(`Authenticated with user ${req.session.user.email}`);
})

app.get('/login', function (req, res) {
    if (req.session.user) {
        res.status(200).send(`Already authenticated with user ${req.session.user.email}`)
    } else {
        res.redirect(client.authorizationUrl({
            scope: 'openid email profile',
            resource: 'http://localhost:3000/oauth/callback',
        }));
    }
})

app.get('/oauth/callback', function (req, res) {
    const params = client.callbackParams(req);
    client.callback('http://localhost:3000/oauth/callback', params ) // => Promise
        .then(function (tokenSet) {
            console.log('received and validated tokens %j', tokenSet);
            console.log('validated ID Token claims %j', tokenSet.claims());
            let { access_token } = tokenSet;
            client.userinfo(access_token) // => Promise
                .then(function (userinfo) {
                    console.log('userinfo %j', userinfo);
                    req.session.user = userinfo;
                    return res.redirect('/');
                }).catch(function (error) {
                    req.session.error = 'Unable to get userinfo';
                    return res.redirect('/login/fail');
            });
        }).catch(function (error) {
        console.log(error);
        req.session.error = 'Unable to get tokens';
        return res.redirect('/login/fail');
    });
})

app.get('/logout', function (req, res) {
    req.session.user = null;
    res.redirect(client.endSessionUrl({
        post_logout_redirect_uri: 'http://localhost:3000/'
    }));
})

app.get('/login/fail', function (req, res) {
    res.send(JSON.stringify({ error: req.session.error }));
    delete res.session.error; // remove from further requests
})

app.listen(3000, () => console.log(`NodeJS app listening at http://localhost:3000`));


