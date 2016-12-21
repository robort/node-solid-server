/**
 * 'Discover Identity Provider' handler.
 * @module provider
 */
module.exports = discoverProvider

const validUrl = require('valid-url')
const request = require('request')
const li = require('li')
// const debug = require('../../debug')
// const util = require('../../utils')

function discoverProvider () {
  return (req, res, next) => {
    if (!validUrl.isUri(req.body.webid)) {
      return res.status(400).send('This is not a valid URI')
    }

    let ldp = req.app.locals.ldp
    if (ldp.auth !== 'oidc') {
      res
        .status(500)
        .send('Invalid signin method - oidc not enabled')
      return
    }
    // let baseUrl = util.uriBase(req)

    // Save the previously-requested URL to session
    // (so that the user can be redirected to it after signin)
    // let returnToUrl = req.body.returnToUrl
    // if (returnToUrl) {
    //   req.session.returnToUrl = returnToUrl
    //   debug.oidc('Saving returnToUrl in session as: ' + returnToUrl)
    // } else {
    //   debug.oidc('Not saving returnToUrl to session (not found)!')
    // }

    // Discover the OIDC issuer from the WebID (or account URL)
    // via an OPTIONS request and its `oidc.issuer` link header
    request({ method: 'OPTIONS', uri: req.body.webid }, function (err, response) {
      if (err) {
        res.status(400).send('Did not find a valid endpoint')
        return
      }
      if (!response.headers.link) {
        res.status(400).send('The URI requested is not a valid endpoint')
        return
      }

      const linkHeaders = li.parse(response.headers.link)
      if (!linkHeaders['oidc.issuer']) {
        res.status(400).send('The URI requested is not a valid endpoint')
        return
      }
      let issuer = linkHeaders['oidc.issuer']

      // load the signin url for the issuer
      let multiRpClient = req.app.locals.oidc.clients
      if (!multiRpClient) {
        res.status(500).send('OIDC multi-rp client not initialized')
        return
      }
      multiRpClient.authUrlForIssuer(issuer, req.session)
        .then((authUrl) => {
          res.redirect(authUrl)
        })
        .catch(next)
    })
  }
}