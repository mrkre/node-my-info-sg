const _ = require('lodash');
const Promise = require('bluebird');
const crypto = require('crypto');
const querystring = require('querystring');
const restClient = require('superagent-bluebird-promise');
const securityHelper = require('./security');

class MyInfoClient {
  constructor(options) {
    this._authApiUrl = `${options.baseUrl}/com/v3/authorise`;
    this._personApiUrl = `${options.baseUrl}/com/v3/person`;
    this._tokenApiUrl = `${options.baseUrl}/com/v3/token`;
    this._authLevel = options.authLevel;
    this._clientId = options.clientId;
    this._clientSecret = options.clientSecret;
    this._privateKeyContent = options.privateKeyContent;
    this._publicCertContent = options.publicCertContent;
    this._redirectUrl = options.redirectUrl;
  }

  getAuthoriseUrl(purpose, attributes) {
    const state = crypto.randomBytes(16).toString('hex');
    const authoriseUrl = `${this._authApiUrl}?client_id=${this._clientId
    }&attributes=${attributes.join(',')
    }&purpose=${purpose
    }&state=${state
    }&redirect_uri=${this._redirectUrl}`;
    return { authoriseUrl, state };
  }

  getToken(code) {
    const self = this;

    return new Promise(((resolve, reject) => {
      const { _authLevel } = self;
      const { _clientId } = self;
      const { _clientSecret } = self;
      const { _privateKeyContent } = self;
      const { _redirectUrl } = self;
      const { _tokenApiUrl } = self;

      const cacheCtl = 'no-cache';
      const contentType = 'application/x-www-form-urlencoded';
      const method = 'POST';

      // assemble params for Token API
      const strParams = `${'grant_type=authorization_code'
        + '&code='}${code
      }&redirect_uri=${_redirectUrl
      }&client_id=${_clientId
      }&client_secret=${_clientSecret}`;
      const params = querystring.parse(strParams);


      // assemble headers for Token API
      const strHeaders = `Content-Type=${contentType}&Cache-Control=${cacheCtl}`;
      const headers = querystring.parse(strHeaders);

      // Add Authorisation headers for connecting to API Gateway
      let authHeaders = null;
      if (_authLevel == 'L0') {
        // No headers
      } else if (_authLevel == 'L2') {
        authHeaders = securityHelper.generateAuthorizationHeader(
          _tokenApiUrl,
          params,
          method,
          contentType,
          _authLevel,
          _clientId,
          _privateKeyContent,
          _clientSecret,
        );
      } else {
        throw new Error('Unknown Auth Level');
      }

      if (!_.isEmpty(authHeaders)) {
        _.set(headers, 'Authorization', authHeaders);
      }


      const request = restClient.post(_tokenApiUrl);

      // Set headers
      if (!_.isUndefined(headers) && !_.isEmpty(headers)) request.set(headers);

      // Set Params
      if (!_.isUndefined(params) && !_.isEmpty(params)) request.send(params);

      request
        .buffer(true)
        .end((callErr, callRes) => {
          if (callErr) {
            // ERROR
            reject(callErr);
          } else {
            // SUCCESSFUL
            const data = {
              body: callRes.body,
              text: callRes.text,
            };

            const accessToken = data.body.access_token;
            if (accessToken == undefined || accessToken == null) {
              reject(new Error('ACCESS TOKEN NOT FOUND'));
            }

            resolve({ accessToken });
          }
        });
    }));
  }

  getPerson(accessToken, attributes) {
    const self = this;

    return new Promise(((resolve, reject) => {
      const { _authLevel } = self;
      const { _privateKeyContent } = self;
      const { _publicCertContent } = self;


      // validate and decode token to get UINFIN
      const decoded = securityHelper.verifyJWS(accessToken, _publicCertContent);
      if (decoded == undefined || decoded == null) {
        reject(new Error('INVALID TOKEN'));
      }


      const uinfin = decoded.sub;
      if (uinfin == undefined || uinfin == null) {
        reject(new Error('UINFIN NOT FOUND'));
      }

      // **** CALL PERSON API ****
      const request = self._createPersonRequest(uinfin, accessToken, attributes.join(','));

      // Invoke asynchronous call
      request
        .buffer(true)
        .end((callErr, callRes) => {
          if (callErr) {
            reject(callErr);
          } else {
            // SUCCESSFUL
            const data = {
              body: callRes.body,
              text: callRes.text,
            };
            let personData = data.text;
            if (personData == undefined || personData == null) {
              reject(new Error('PERSON DATA NOT FOUND'));
            } else if (_authLevel == 'L0') {
              personData = JSON.parse(personData);
              // personData = securityHelper.verifyJWS(personData, _publicCertContent);

              if (personData == undefined || personData == null) {
                reject(new Error('INVALID DATA OR SIGNATURE FOR PERSON DATA'));
              }

              // successful. return data back to frontend
              resolve({ person: personData });
            } else if (_authLevel == 'L2') {
              const jweParts = personData.split('.'); // header.encryptedKey.iv.ciphertext.tag
              securityHelper.decryptJWE(jweParts[0], jweParts[1], jweParts[2], jweParts[3], jweParts[4], _privateKeyContent)
                .then((personDataJWS) => {
                  if (personDataJWS == undefined || personDataJWS == null) {
                    reject(new Error('INVALID DATA OR SIGNATURE FOR PERSON DATA'));
                  }

                  const decodedPersonData = securityHelper.verifyJWS(personDataJWS, _publicCertContent);
                  if (decodedPersonData == undefined || decodedPersonData == null) {
                    reject(new Error('INVALID DATA OR SIGNATURE FOR PERSON DATA'));
                  }

                  // successful. return data back to frontend
                  resolve({ person: decodedPersonData });
                });
            } else {
              reject(new Error('Unknown Auth Level'));
            } // end else
          }
        }); // end asynchronous call
    }));
  }

  _createPersonRequest(uinfin, validToken, attributes) {
    const _attributes = attributes;
    const { _authLevel } = this;
    const { _clientId } = this;
    const { _clientSecret } = this;
    const { _personApiUrl } = this;
    const { _privateKeyContent } = this;

    const url = `${_personApiUrl}/${uinfin}/`;
    const cacheCtl = 'no-cache';
    const method = 'GET';

    // assemble params for Person API
    const strParams = `client_id=${_clientId
    }&attributes=${_attributes}`;

    const params = querystring.parse(strParams);

    // assemble headers for Person API
    const strHeaders = `Cache-Control=${cacheCtl}`;
    const headers = querystring.parse(strHeaders);

    // Add Authorisation headers for connecting to API Gateway
    const authHeaders = securityHelper.generateAuthorizationHeader(
      url,
      params,
      method,
      '', // no content type needed for GET
      _authLevel,
      _clientId,
      _privateKeyContent,
      _clientSecret,
    );

    // NOTE: include access token in Authorization header as "Bearer " (with space behind)
    if (!_.isEmpty(authHeaders)) {
      _.set(headers, 'Authorization', `${authHeaders},Bearer ${validToken}`);
    } else {
      _.set(headers, 'Authorization', `Bearer ${validToken}`);
    }

    // invoke person API
    const request = restClient.get(url);

    // Set headers
    if (!_.isUndefined(headers) && !_.isEmpty(headers)) request.set(headers);

    // Set Params
    if (!_.isUndefined(params) && !_.isEmpty(params)) request.query(params);

    return request;
  }
}

module.exports = MyInfoClient;
