// This module provides Cloud Identity functions

// dotenv is used to read properties from .env file
const dotenv = require('dotenv');

// The OAuth module is used to get an Access Token
const clientCreds = require('./oauth-client-creds.js').OAuthClientCreds;

// Required CI Endpoints
var userEndpoint = '/v2.0/Users';
var otpEndpointEmail = '/v1.0/authnmethods/emailotp/transient/verification';
var otpEndpointSMS = '/v1.0/authnmethods/smsotp/transient/verification';
var passwordEndpoint = '/v2.0/Users/authentication';
var qrEndpoint = '/v2.0/factors/qr/authenticate';

// load contents of .env into process.env
dotenv.config();

// Read CI Tenant URL from properties
var config  = {
  tenantUrl: process.env.TENANT_URL,
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET
};

var tenant_url = process.env.TENANT_URL;

oauth = new clientCreds(config);

// Function to lookup user information using userID
// Function returns a Promise which will resolve to the user SCIM data
function getUser(userid) {

  var options = {
    url: tenant_url + userEndpoint + '/' + userid,
    method: "GET",
    accept: "application/scim+json"
  };

  return oauth.makeRequest(options);
}

// Function to generate one time password
// Function returns a Promise which will resolve to CI response body
function generateOTP(login_method, userData) {
  var otpData;
  var otpEndpoint;

  // If OTP method is e-mail
  if (login_method == "email") {
    // Set OTP Data for e-mail
    otpData = {
      "otpDeliveryEmailAddress": userData
    }
    // Use Email OTP endpoint
    otpEndpoint = otpEndpointEmail;
  } else { //method is SMS
    // Set OTP Data for SMS
    otpData = {
      "otpDeliveryMobileNumber": userData
    }
    // Use SMS OTP Endpoint
    otpEndpoint = otpEndpointSMS;
  }

  var options = {
    url: tenant_url + otpEndpoint,
    method: "POST",
    data: otpData
  }
  return oauth.makeRequest(options);
}

// Function to validate OTP
// It returns a Promise which resolves to the CI Response body
// It needs the response from initate call which contains method
// and the transaction ID
function validateOTP(otpInitResponse, otp) {

  // Build POST Data
  var postData = {
    "otp": otp
  }

  //Set the OTP Endpoint to SMS or E-mail based on methodType
  var otpEndpoint;
  if (otpInitResponse.methodType == "smsotp") {
    otpEndpoint = otpEndpointSMS;
  } else {
    otpEndpoint = otpEndpointEmail;
  }

  // Make call to the REST endpoint for the transaction
  // Pass in the OTP that was received
  var options = {
    url: tenant_url + otpEndpoint + '/' + otpInitResponse.id,
    method: "POST",
    data: postData
  }
  return oauth.makeRequest(options);
}

// Function to initiate QRLogin
// Returns a Promise which resolves to the CI Response Body
// Input is the Verify Registration Id
function initiateQRLogin(regId) {

  var options = {
    url: tenant_url + qrEndpoint + '?profileId=' + regId,
    method: "GET"
  }

  return oauth.makeRequest(options);
}

// Function to validate QRLogin
// Returns a Promise which resolves to the CI Response Body
// Takes the response from the initiation which contains transaction ID
// and DSI
function validateQRLogin(qrInitResponse) {

  var qr_id = qrInitResponse.id;
  var qr_dsi = qrInitResponse.dsi;

  var options = {
    url: tenant_url + qrEndpoint + '/' + qr_id + '?dsi=' + qr_dsi,
    method: "GET"
  };

  return oauth.makeRequest(options);
}

// Function to check user password (and get user information)
// This function returns a Promise which resolves to the response from CI
// It takes uid and pw to be checked against CI Cloud Directory
function passwordLogin(uid, pw) {
  var postData = {
    "userName": uid,
    "password": pw,
    "schemas": ["urn:ietf:params:scim:schemas:ibm:core:2.0:AuthenticateUser"]
  }

  var options = {
    method: "POST",
    accept: "application/scim+json",
    url: tenant_url + passwordEndpoint + '?returnUserRecord=true',
    data: postData
  };
  return oauth.makeRequest(options);
}

module.exports = {
  getUser: getUser,
  generateOTP: generateOTP,
  validateOTP: validateOTP,
  initiateQRLogin: initiateQRLogin,
  validateQRLogin: validateQRLogin,
  passwordLogin: passwordLogin
};
