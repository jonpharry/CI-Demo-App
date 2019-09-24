const express = require('express');
var router = express.Router();

// Cloud Identity Module makes calls to CI
const ci = require('../cloudidentity.js');

// dotenv is used to read properties from .env file
const dotenv = require('dotenv');

// load contents of .env into process.env
dotenv.config();

// Read Verify registration ID from .env file
var reg_id = process.env.VERIFY_REG_ID;

// Handle GET request for login page
router.get('/', function(req, res, _next) {
  // Call to CI to initiate QRCode Login flow
  ci.initiateQRLogin(reg_id).then((qrTxn) => {
    // Store the response in session.  Needed for validation.
    req.session.qrtxn = qrTxn;
    // Render the login page.  The QR Code image is sent (base64 encoded)
    // in qrCode.  It is rendered directly on the page.
    res.render('userlogin', {
      title: 'Login',
      qrCode: qrTxn.qrCode
    });
  });
});

// Handle GET request for /userlogin/qrcheck
// This endpoint is intended to be accessed by client-side JavaScript
// on the login page which polls to see if QRLogin has been completed
router.get('/qrcheck', function(req, res, _next) {

  // Call QRLogin validation function.
  // Pass in the response from initation which includes transaction id
  // and DSI needed for the validation check.
  ci.validateQRLogin(req.session.qrtxn).then((body) => {
    // Check if response contains state parameter
    if (body.state) {
      // If state is "SUCCESS" it means QRLogin has completed
      if (body.state == "SUCCESS") {
        // Mark the session as authenticated
        req.session.authenticated = true;
        // Clean up data from session
        delete req.session.qrtxn
        // Save userId of user identified by QRCode Login
        req.session.userId = body.userId;

        // Call getUser function to get user information
        ci.getUser(req.session.userId).then((user) => {
          // Add user to session
          req.session.user = user;

          // If a post-authentication target is set in session
          if (req.session.afterlogin) {
            // set url to this value and clean from session
            url = req.session.afterlogin;
            delete req.session.afterlogin;
          } else { // no target in session
            // set url to userhome
            url = "userhome";
          }
          // Respond to caller with SUCCESS
          // Also provide indication of post-authentication target
          res.json({
            "state": "SUCCESS",
            "next": url
          });
        });
      } else { // state is not SUCCESS
        // Return the state to the caller
        res.json({
          "state": body.state
        });
      }
    } else { // bad response
      // return error state to the caller
      res.json({
        "state": "error"
      });
    }
  });
});

// Handle POST to /userlogin/pwdcheck
// This is where username/password is submitted for validation
router.post('/pwdcheck', function(req, res, _next) {

  // Check both username and password fields are available
  if (req.body.username && req.body.password) {
    // Call CI to check username and password
    // If username and password good, id in response will contain
    // CI user ID for authenticated user.
    ci.passwordLogin(req.body.username, req.body.password).then((userJson) => {
      // Attempt to populate session with id from response
      req.session.userId = userJson.id;

      // If userId in session not populated (authentication failed)
      if (!(req.session.userId)) {
        // Return an error page
        res.render('error', {
          message: "Something went wrong",
          status: "400"
        });
      } else { // Authentication was successful.
        // Mark session authenticated
        req.session.authenticated = true
        // Populate user in session
        req.session.user= userJson;

        // Clean up (unused) QR Code data from session
        delete req.session.qrtxn;

        // If a post-authentication target available in session
        if (req.session.afterlogin) {
          // set url variable with this target
          var url = req.session.afterlogin;
          // clean up data in session
          delete req.session.afterlogin;
          // Redirect to the target URL
          res.redirect('/' + url);
        } else { // No target available in session
          // Redirect to user home page
          res.redirect('/userhome');
        }
      }
    }).catch(e => {
      res.render('error', {
        message: "Something went wrong",
        status: "500"
      });
      console.log("Error: " + e.error);
    });
  } else { // username and/or password missing from POST body
    console.log("Username and password should be provided");
    res.render('error', {
      message: "Both username password should be provided, try again",
      status: "400"
    });
  }
});

module.exports = router;
