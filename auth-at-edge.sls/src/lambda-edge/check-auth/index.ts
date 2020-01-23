// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import { stringify as stringifyQueryString } from "querystring";
import { createHash, randomBytes } from "crypto";
import { CloudFrontRequestHandler } from "aws-lambda";
import { validate } from "./validate-jwt";
import {
  getConfig,
  extractAndParseCookies,
  decodeToken,
} from "../shared/shared";

// Allowed characters per https://tools.ietf.org/html/rfc7636#section-4.1
const SECRET_ALLOWED_CHARS =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
const PKCE_LENGTH = 43; // Should be between 43 and 128 - per spec
const NONCE_LENGTH = 16; // how many characters should your nonces be?

// const {
//   clientId,
//   oauthScopes,
//   cognitoAuthDomain,
//   redirectPathSignIn,
//   redirectPathAuthRefresh,
//   tokenIssuer,
//   tokenJwksUri,
//   cookieSettings,
//   cloudFrontHeaders,
// } = getConfig();
// const {
//   oauthScopes,
//   redirectPathSignIn,
//   redirectPathAuthRefresh,

// } = getConfig();

export const handler: CloudFrontRequestHandler = async event => {
  console.log('CHECK-AUTH HANDLER');
  const request = event.Records[0].cf.request;
  if (!request.origin) {
    throw "This must be an origin-request, not a viewer-request";
  }
  const origin = request.origin.s3 || request.origin.custom || {};
  console.log(origin.customHeaders);

  const {
    clientId,
    oauthScopes,
    cognitoAuthDomain,
    redirectPathSignIn,
    redirectPathAuthRefresh,
    tokenIssuer,
    tokenJwksUri,
    cookieSettings,
    cloudFrontHeaders,
  } = getConfig(origin.customHeaders);

  const domainName = request.headers["host"][0].value;
  console.log('DomainName');
  console.log(domainName);
  const requestedUri = `${request.uri}${
    request.querystring ? "?" + request.querystring : ""
  }`;
  console.log('RequestedURI');
  console.log(requestedUri);
  const nonce = generateNonce();
  console.log('Nonce');
  console.log(nonce);
  try {
    const { tokenUserName, idToken, refreshToken } = extractAndParseCookies(
      request.headers,
      clientId,
    );
    console.log('TokenUserName');
    console.log(tokenUserName);
    console.log('idToken');
    console.log(idToken);
    console.log('refreshToken');
    console.log(refreshToken);
    if (!tokenUserName || !idToken) {
      throw new Error("No valid credentials present in cookies");
    }
    // If the token has (nearly) expired and there is a refreshToken: refresh tokens
    const { exp } = decodeToken(idToken);
    if (Date.now() / 1000 - 60 > exp && refreshToken) {
      return {
        status: "307",
        statusDescription: "Temporary Redirect",
        headers: {
          location: [
            {
              key: "location",
              value: `https://${domainName}${redirectPathAuthRefresh}?${stringifyQueryString(
                { requestedUri, nonce },
              )}`,
            },
          ],
          "set-cookie": [
            {
              key: "set-cookie",
              value: `spa-auth-edge-nonce=${encodeURIComponent(nonce)}; ${
                cookieSettings.nonce
              }`,
            },
          ],
          ...cloudFrontHeaders,
        },
      };
    }
    // Check for valid a JWT. This throws an error if there's no valid JWT:
    await validate(idToken, tokenJwksUri, tokenIssuer, clientId);
    // Return the request unaltered to allow access to the resource:
    return request;
  } catch (err) {
    const { pkce, pkceHash } = generatePkceVerifier();
    console.log("pkce");
    console.log(pkce);
    console.log("pkcehash");
    console.log(pkceHash);
    const loginQueryString = stringifyQueryString({
      redirect_uri: `https://${domainName}${redirectPathSignIn}`,
      response_type: "code",
      client_id: clientId,
      state: JSON.stringify({ nonce, requestedUri }),
      scope: oauthScopes.join(" "),
      code_challenge_method: "S256",
      code_challenge: pkceHash,
    });
    console.log("LoginQueryString");
    console.log(loginQueryString);
    return {
      status: "307",
      statusDescription: "Temporary Redirect",
      headers: {
        location: [
          {
            key: "location",
            value: `https://${cognitoAuthDomain}/oauth2/authorize?${loginQueryString}`,
          },
        ],
        "set-cookie": [
          {
            key: "set-cookie",
            value: `spa-auth-edge-nonce=${encodeURIComponent(nonce)}; ${
              cookieSettings.nonce
            }`,
          },
          {
            key: "set-cookie",
            value: `spa-auth-edge-pkce=${encodeURIComponent(pkce)}; ${
              cookieSettings.nonce
            }`,
          },
        ],
        ...cloudFrontHeaders,
      },
    };
  }
};

function generatePkceVerifier() {
  const pkce = [...new Array(PKCE_LENGTH)]
    .map(() => randomChoiceFromIndexable(SECRET_ALLOWED_CHARS))
    .join("");
  return {
    pkce,
    pkceHash: createHash("sha256")
      .update(pkce, "utf8")
      .digest("base64")
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_"),
  };
}

function generateNonce() {
  return [...new Array(NONCE_LENGTH)]
    .map(() => randomChoiceFromIndexable(SECRET_ALLOWED_CHARS))
    .join("");
}

function randomChoiceFromIndexable(indexable: string) {
  if (indexable.length > 256) {
    throw new Error(`indexable is too large: ${indexable.length}`);
  }
  const chunks = Math.floor(256 / indexable.length);
  let randomNumber: number;
  do {
    randomNumber = randomBytes(1)[0];
  } while (randomNumber >= indexable.length * chunks);
  const index = randomNumber % indexable.length;
  return indexable[index];
}
