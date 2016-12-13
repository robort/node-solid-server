module.exports = createApp

var express = require('express')
var session = require('express-session')
var uuid = require('uuid')
var cors = require('cors')
var LDP = require('./ldp')
var LdpMiddleware = require('./ldp-middleware')
var proxy = require('./handlers/proxy')
var IdentityProvider = require('./identity-provider')
var vhost = require('vhost')
var path = require('path')
var fs = require('fs')
var EmailService = require('./email-service')
const url = require('url')
const AccountRecovery = require('./account-recovery')
const capabilityDiscovery = require('./capability-discovery')
const bodyParser = require('body-parser')
const API = require('./api')
const authentication = require('./handlers/authentication')
const debug = require('./debug')
const KVPFileStore = require('kvplus-files')
const oidcHandler = require('./handlers/oidc')
const { MultiRpClient } = require('solid-multi-rp-client')
const ResourceAuthenticator = require('oidc-rs')
const OIDCProvider = require('oidc-op')
const UserStore = require('./user-store')

var corsSettings = cors({
  methods: [
    'OPTIONS', 'HEAD', 'GET', 'PATCH', 'POST', 'PUT', 'DELETE'
  ],
  exposedHeaders: 'Authorization, User, Location, Link, Vary, Last-Modified, ETag, Accept-Patch, Accept-Post, Updates-Via, Allow, Content-Length',
  credentials: true,
  maxAge: 1728000,
  origin: true,
  preflightContinue: true
})

function createApp (argv = {}) {
  var ldp = new LDP(argv)
  var app = express()
  var localOidcConfig = argv.oidc

  app.use(corsSettings)

  app.options('*', (req, res, next) => {
    res.status(204)
    next()
  })

  // check if we have master ACL or not
  var masterAcl
  var checkMasterAcl = function (req, callback) {
    if (masterAcl) {
      return callback(true)
    }

    ldp.exists(req.hostname, '/' + ldp.suffixAcl, function (err) {
      if (!err) {
        masterAcl = true
      }
      callback(!err)
    })
  }

  // Setting options as local variable
  app.locals.ldp = ldp
  app.locals.appUrls = argv.apps // used for service capability discovery
  app.locals.localOidcConfig = localOidcConfig
  app.locals.rootUrl = argv.rootUrl

  if (argv.email && argv.email.host) {
    app.locals.email = new EmailService(argv.email)
  }

  var sessionSettings = {
    secret: ldp.secret || uuid.v1(),
    saveUninitialized: false,
    resave: false,
    rolling: true
  }

  // Cookies should set to be secure if https is on
  if (ldp.webid || ldp.idp) {
    sessionSettings.cookie = {
      domain: '.ldnode.local',
      secure: true,
      maxAge: 24 * 60 * 60 * 1000
    }
  }

  // Set X-Powered-By
  app.use(function (req, res, next) {
    res.set('X-Powered-By', 'solid-server')
    next()
  })

  // Set default Allow methods
  app.use(function (req, res, next) {
    res.set('Allow', 'OPTIONS, HEAD, GET, PATCH, POST, PUT, DELETE')
    next()
  })

  app.use('/', capabilityDiscovery())

  // Session
  app.use(session(sessionSettings))

  // OpenID Connect Auth
  if (localOidcConfig && ldp.auth === 'oidc') {
    // Return 'oidc.issuer' link rel header on OPTIONS requests (for discovery)
    app.options('*', oidcHandler.oidcIssuerHeader)
    debug.oidc('Initializing oidc clients at startup.')
    let userStore = new UserStore({path: './db'})
    userStore.initCollections()  // sync, ensure storage dirs created
    let oidc = {
      auth: new ResourceAuthenticator({ defaults: { handleErrors: false, optional: true } }),  // oidc-rs
      clients: new MultiRpClient({ localConfig: localOidcConfig }),       // used for initial sign in
      config: localOidcConfig,
      users: userStore
    }
    app.locals.oidc = oidc
    // Initialize the OIDC Resource Server routes/api
    app.use('/', express.static(path.join(__dirname, '../static/oidc')))
    // Sign in (provider discovery) / sign out API
    app.use('/api/oidc', oidcHandler.api(oidc))
    // Minimal provider
    let provider = new OIDCProvider({
      issuer: localOidcConfig.issuer
      //issuer: 'https://forge.anvil.io'
    })
    // INITIALIZE THE KEY CHAIN, SERIALIZE, PERSIST
    provider.initializeKeyChain()
      .then(keys => {
        // fs.writeFileSync('provider.json', JSON.stringify(provider, null, 2))
        console.log('Provider keychain initialized')
      })
      .catch(err => {
        debug.oidc(err)
        console.log(err)
        throw err
      })
    oidcStore = new KVPFileStore({
      path: './db/oidc',
      collections: ['codes', 'clients', 'tokens', 'refresh']
    })
    oidcStore.initCollections()
    provider.inject({ backend: oidcStore })
    provider.inject({
      host: {
        authenticate: (authRequest) => {
          console.log('AUTHENTICATE injected method')
          let session = authRequest.req.session
          if (session.identified && session.userId) {
            authRequest.subject = {
              _id: session.userId  // put webId into the IDToken's subject claim
            }
          } else {
            // User not authenticated, send them to signin
            let signinUrl = url.parse(url.resolve(app.locals.rootUrl, '/signin/'))
            signinUrl.query = authRequest.req.query
            signinUrl = url.format(signinUrl)
            authRequest.subject = null
            console.log('Redirecting to /signin', signinUrl)
            authRequest.res.redirect(signinUrl)
          }
          return authRequest
        },
        obtainConsent: (authRequest) => {
          if (authRequest.subject) {
            authRequest.consent = true
            authRequest.scope = authRequest.params.scope
            console.log('OBTAINED CONSENT')
          }
          return authRequest
        }
      }
    })
    // Initialize the OIDC Identity Provider routes/api
    let oidcApi = require('oidc-op-express')(provider)
    app.use('/', oidcApi)
    app.use('/', oidc.auth.authenticate())
  }

  // Adding proxy
  if (ldp.proxy) {
    proxy(app, ldp.proxy)
  }

  if (ldp.webid) {
    var accountRecovery = AccountRecovery({ redirect: '/' })
    // adds GET /api/accounts/recover
    // adds POST /api/accounts/recover
    // adds GET /api/accounts/validateToken
    app.use('/api/accounts/', accountRecovery)
  }

  // Adding Multi-user support
  if (ldp.webid) {
    var idp = IdentityProvider({
      store: ldp,
      suffixAcl: ldp.suffixAcl,
      suffixMeta: ldp.suffixMeta,
      settings: 'settings',
      inbox: 'inbox',
      auth: ldp.auth
    })

    var needsOverwrite = function (req, res, next) {
      checkMasterAcl(req, function (found) {
        if (!found && !ldp.idp) {
          // this allows IdentityProvider to overwrite root acls
          idp.middleware(true)(req, res, next)
        } else if (ldp.idp) {
          idp.middleware(false)(req, res, next)
        } else {
          next()
        }
      })
    }

    // adds POST /api/accounts/new
    // adds POST /api/accounts/newCert
    app.get('/', idp.get.bind(idp))
    app.post(['/signin', '/api/accounts/signin'],
      bodyParser.urlencoded({ extended: false }), API.accounts.signin())
    app.post('/api/accounts/discover',
      bodyParser.urlencoded({ extended: false }), API.accounts.discoverProvider())
    app.use('/api/accounts', needsOverwrite)
    app.get('/signout', API.accounts.signout())
    app.post('/api/accounts/signout', API.accounts.signout())

    app.post('/api/messages', authentication, bodyParser.urlencoded({ extended: false }), API.messages.send())
  }

  if (argv.apiApps) {
    app.use('/api/apps', express.static(argv.apiApps))
  }

  if (ldp.idp) {
    app.use(vhost('*', LdpMiddleware(corsSettings)))
  }

  app.get('/', function (req, res, next) {
    // Do not bother showing html page can't be read
    if (!req.accepts('text/html') || !ldp.webid) {
      return next()
    }

    checkMasterAcl(req, function (found) {
      if (!found) {
        res.set('Content-Type', 'text/html')
        var signup = path.join(__dirname, '../static/signup.html')
        res.sendFile(signup)
      } else {
        next()
      }
    })
  })
  app.use('/', LdpMiddleware(corsSettings))

  return app
}
