// This module provides a function for obtaining an
// Access Token from IBM Security Verify using client credentials

// Axios is used for REST API calls
const axios = require('axios');

// qs used for URI encoding
const qs = require('query-string');

// fs is used for filesystem access
const fs = require('fs');

// Initialize a Date helper
var date = new Date();

// Function to get a new Access Token
// Adds expiry time and stores to filesystem and local variable
function callTokenEndpoint(config) {
  return new Promise((resolve, _reject) => {
    console.log("Getting new token");
    // Call the SDK Auth Client to get a token
    // Requires one input so send dummy value
    getToken(config).then(generated_token => {

      // Add absolute expiry time to the token data
      // Calculated from current time and expires_in
      generated_token.expirytime = date.getTime() + (generated_token.expires_in * 1000);

      console.log("response : " + JSON.stringify(generated_token));

      // Persist the token information on filesystem
      fs.writeFile(`access_token_${config.clientId}.json`, JSON.stringify(generated_token), function(err, _result) {
        if (err) console.log('error', err);
      });

      // Store the token in global variable and resolve Promise
      this.token = generated_token;
      resolve(generated_token);
    });
  });
}

/**
 * @function getToken Retrieves a token using client_credentials
 * @returns {Promise<object>} Response object from login containing token
 */
function getToken(config) {

  let path = `${config.tenantUrl}/v1.0/endpoint/default/token`;

  const data = {
    client_id: config.clientId,
    client_secret: config.clientSecret,
    grant_type: "client_credentials",
  };

  let encodedData = qs.stringify(data);

  let options = {
    method: 'POST',
    url: path,
    contentType: 'application/x-www-form-urlencoded',
    data: encodedData
  };

  return apiRequest(options);
}

/**
 * @function apiRequest Makes an API request
 * @param {object} request Object containing request type, url paths to make a valid api request
 * @param {string} accessToken Access token string
 * Returns promise resolve json payload || reject error message
 */

let apiRequest = async function(request, accessToken) {
    let headers = {};
    if (request.accept) {
      headers['Accept'] =  `${request.accept}, text/html`;
    } else {
      headers['Accept'] = 'application/json';
    }

    if (request.contentType) {
      headers['Content-Type'] = request.contentType;
    } else {
      headers['Content-Type'] =  'application/json';
    }
    if (accessToken && accessToken !== null) {
      headers['Authorization'] = `Bearer ${accessToken}`;
    }
    headers['Cache-Control'] = 'no-cache';
    request.headers = headers;
    request.withCredentials = true;

    if (request.data) {
      let data = request.data;
      if (typeof data === 'object' || typeof data === 'boolean') {
        request.data = JSON.stringify(data);
      }
    }

    let response = await axios(request);

    if (response.status >= 200 && response.status < 300) {
      let finalResponse = undefined;
      if (response.status === 204) {
        return(response);
      }
      try {
        finalResponse = JSON.parse(response.data);
      } catch (error) {
        finalResponse = response.data;
      }
      return finalResponse;
    } else if (response.status >= 400 && response.status < 500) {
          try {
            err = new Error("HTTP Error.  Status: " + response.status + " Message: " + JSON.stringify(response.data));
          } catch (error) {
            err = new Error("HTTP Error.  Status: " + response.status + " Message: " + response.data);
          }
          throw err;
    } else if (response.status >= 500) {
          let serverErrorMessage = response.statusText || 'Internal Server Error';
          throw `Error: ${response.status} ${serverErrorMessage}`;
    }
}


class OAuthClientCreds {

  constructor(config) {
    this.config = config;
    //    tenantUrl: process.env.TENANT_URL,
    //    clientId: process.env.CLIENT_ID,
    //    clientSecret: process.env.CLIENT_SECRET,
    //    scope: '',
    //    token: existingToken object
    if (this.config.token) {
      this.token = this.config.token;
    }
  }

  // Function to get an Access Token from Cloud Identity
  // The token is only retrieved if current stored token has expired
  getAccessToken() {
    return new Promise((resolve, reject) => {

      var storedToken = this.token
      // If stored token exists
      if (storedToken) {
        // If stored token is good for at least 30 seconds...
        if (storedToken.expirytime > date.getTime() + 30000) {
          console.log("Token in memory is good");
          // Resolve Promise with stored token
          resolve(storedToken);
        } else { // Stored token is no good
          console.log("Token in memory is bad");
          // Get a new token and resolve Promise with that
          callTokenEndpoint(this.config).then((token) => {
            this.token = token;
            resolve(token);
          }).catch(err => {reject(err)});
        }
      } else { // No stored token exists
        var stringToken = null
        try { //Attempt to read token data from file
          stringToken = fs.readFileSync(`access_token_${this.config.clientId}.json`)
        } catch (error) {}; //Do nothing on failure
        // If a token was read from file
        if (stringToken) {
          console.log("Loaded token : " + stringToken);
          // Parse file contents and store in global variable
          storedToken = JSON.parse(stringToken);
          this.token = storedToken;
          // If token is good for at least 30 seconds
          if (storedToken.expirytime > date.getTime() + 30000) {
            console.log("Loaded token lifetime is good");

            // Run an introspection to make sure it is really OK
            this.introspectToken(storedToken).then(r => {

              // If introspection returns active then return this token
              if (r.active == true) {
                console.log("Token is active");
                resolve(storedToken);
              } else { // If token is not active
                console.log("Token expired");
                // Get a new token and return that one.
                callTokenEndpoint(this.config).then((token) => {
                  this.token = token;
                  resolve(token);
                }).catch(err => {reject(err)});
              }
            });
          } else { // Token has expired
            console.log("Loaded token lifefime is bad");
            // Get a new token and return that one.
            callTokenEndpoint(this.config).then((token) => {
              this.token = token;
              resolve(token);
            });
          }
        } else { // If no stored token
          console.log("No stored token");
          // Get a new token and return that one.
          callTokenEndpoint(this.config).then((token) => {
            this.token = token;
            resolve(token);
          }).catch(err => {reject(err)});
        }
      }
    });
  }

  /**
   * @function ROPC gets an Access Token using Password credentials
   * @param {string} username The username to be presented
   * @param {string} password The password to be presented
   * @returns {Promise<object>} Response object with information about the supplied token
   */
  performRopc(username, password) {
    if (!username) {
      return Promise.reject(new Error('Username parameter is required'));
    }

    if (!password) {
      return Promise.reject(new Error('Password parameter is required'));
    }

    let path = `${this.config.tenantUrl}/v1.0/endpoint/default/token`;

    let data = {
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      grant_type: 'password',
      username: username,
      password: password,
      scope: "oidc test",
      notoken: true
    };

    let encodedData = qs.stringify(data);

    let options = {
      method: 'POST',
      url: path,
      contentType: 'application/x-www-form-urlencoded',
      data: encodedData
    };

    return this.makeRequest(options);
  }

  /**
   * @function introspectToken Introspects a token for more information
   * @param {object} token The token to be inspected containing access_token, refresh_token ...
   * @returns {Promise<object>} Response object with information about the supplied token
   */
  introspectToken(token) {
    if (!this.isToken(token)) {
      return Promise.reject(new Error('Token parameter is not a valid token'));
    }

    let path = `${this.config.tenantUrl}/v1.0/endpoint/default/introspect`;

    let data = {
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      token: token.access_token
    };

    let encodedData = qs.stringify(data);

    let options = {
      method: 'POST',
      url: path,
      contentType: 'application/x-www-form-urlencoded',
      data: encodedData,
      notoken: true
    };

    return this.makeRequest(options);
  }

  /**
   * @function userInfo Retrieves user information associated with the given token
   * @param {object} token The associated token to inspect the user information of containing access_token, refresh_token ...
   * @returns {Promise<object>} Response object with information about the user of the supplied token
   */
  userInfo(token) {
    if (!this.isToken(token)) {
      return Promise.reject(new Error('Token parameter is not a valid token'));
    }

    let path = `${this.config.tenantUrl}/v1.0/endpoint/default/userinfo`;

    let options = {
      notoken: true,
      method: 'POST',
      url: path,
      contentType: 'application/x-www-form-urlencoded',
      data: qs.stringify({
        access_token: token.access_token
      })
    };

    return this.makeRequest(options);
  }

  /**
   * @function isToken Validates a token
   * @param {object} token The token to check containing access_token, refresh_token ...
   * @returns {boolean} Boolean indicating whether the token is valid
   */
  isToken(token) {
    return !(!token || !token.access_token);
  }

  /**
   * @function revokeToken Revokes a token
   * @param {object} token The token to be revoked containing access_token, refresh_token ...
   * @param {string} tokenType The type of token - 'access_token' or 'refresh_token'
   * @returns {Promise<object>} Response object from revoking the token
   */
  revokeToken(token) {
    return new Promise(async (resolve, reject) => {
    const path = `${this.config.tenantUrl}/v1.0/endpoint/default/revoke`;

    if (!this.token) {
      reject('Token cannot be null');
    }

    let data = {
      notoken: true,
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      token: this.token.access_token
    };

    const encodedData = qs.stringify(data);

    const options = {
      method: 'POST',
      contentType: 'application/x-www-form-urlencoded',
      url: path,
      data: encodedData
    };

    try {
    var result = await this.makeRequest(options);

    if (token.access_token == this.token.access_token) {
      console.log("Cleaning up client token");
      this.token = undefined;

      // Remove token from filesystem
      fs.unlink(`access_token_${this.config.clientId}.json`, function(err) {
        if (err) console.log('error', err);
      });
    }
    resolve(result);
  } catch (err) {reject(err)}
    });
  }

  /**
   * @function makeRequest Makes a request and refreshes token if token is expired
   * @param {object} options Request object containing url path, method, responseType, accept, data to make a valid apiRequest
   * @returns {object} Response object from the request
   */
  makeRequest(options) {
    return new Promise ( async (resolve, reject) => {
    if (arguments.length < 1) {
      reject(new Error('makeRequest(options), 1 parameter required ' + arguments.length + ' were given'));
    }
    if (options.notoken == true) {
      try {
        delete options.notoken;
        const response = await apiRequest(options, null);
        resolve(response);
      } catch (error) {
        if (error.status === 401 && utils.isNode()) {
          reject(new Error('Unauthorized'));
        }
        reject(error);
      }
    } else {
      var token = options.access_token;
      try {
        if (token) {
          delete options.access_token;
        } else {
          token = await this.getAccessToken();
        }
        const response = await apiRequest(options, token.access_token);
        resolve(response);
      } catch (error) {
        if (error.status === 401 && utils.isNode()) {
          reject(new Error('Unauthorized'));
        }
        reject(error);
      }
    }
  });
  }

}

module.exports.OAuthClientCreds = OAuthClientCreds
