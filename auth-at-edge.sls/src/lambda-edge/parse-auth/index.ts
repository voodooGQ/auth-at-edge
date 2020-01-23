// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import {
  parse as parseQueryString,
  stringify as stringifyQueryString,
} from "querystring";
import { CloudFrontRequestHandler } from "aws-lambda";
import {
  getConfig,
  extractAndParseCookies,
  getCookieHeaders,
  httpPostWithRetry,
  createErrorHtml,
} from "../shared/shared";

export const handler: CloudFrontRequestHandler = async event => {
  console.log("PARSE AUTH HANDLER");
  const request = event.Records[0].cf.request;
  console.log("Request");
  console.log(request);
  console.log("Request Body");
  console.log(request.body);
  console.log("RequestQueryString");
  console.log(request.querystring);
  console.log("RequestURI");
  console.log(request.uri);
  if (!request.origin) {
    throw "This must be an origin-request, not a viewer-request";
  }
  const origin = request.origin.s3 || request.origin.custom || {};
  console.log("Custom Headers");
  console.log(origin.customHeaders);
  const {
    clientId,
    oauthScopes,
    cognitoAuthDomain,
    cookieSettings,
    cloudFrontHeaders,
    redirectPathSignIn,
  } = getConfig(origin.customHeaders);
  const domainName = request.headers["host"][0].value;
  console.log("DomainName");
  console.log(domainName);
  let redirectedFromUri = `https://${domainName}`;
  console.log("RedirectedFromUri");
  console.log(redirectedFromUri);

  try {
    const { code, state } = parseQueryString(request.querystring);
    console.log("Code");
    console.log(code);
    console.log("State");
    console.log(state);
    if (
      !code ||
      !state ||
      typeof code !== "string" ||
      typeof state !== "string"
    ) {
      throw new Error(
        'Invalid query string. Your query string should include parameters "state" and "code"',
      );
    }
    const { nonce: currentNonce, requestedUri } = JSON.parse(state);
    console.log("Current Nonce");
    console.log(currentNonce);

    console.log("Requested URI");
    console.log(requestedUri);

    redirectedFromUri += requestedUri || "";
    console.log("redirectedFromUri Update");
    console.log(requestedUri);

    const { nonce: originalNonce, pkce } = extractAndParseCookies(
      request.headers,
      clientId,
    );
    console.log("Original Nonce");
    console.log(originalNonce);

    console.log("pkce");
    console.log(pkce);

    if (!currentNonce || !originalNonce || currentNonce !== originalNonce) {
      if (!originalNonce) {
        throw new Error(
          "Your browser didn't send the nonce cookie along, but it is required for security (prevent CSRF).",
        );
      }
      throw new Error("Nonce mismatch");
    }
    const body = stringifyQueryString({
      grant_type: "authorization_code",
      client_id: clientId,
      redirect_uri: `https://${domainName}${redirectPathSignIn}`,
      code,
      code_verifier: pkce,
    });
    console.log("body");
    console.log(body);

    const res = await httpPostWithRetry(
      `https://${cognitoAuthDomain}/oauth2/token`,
      body,
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } },
    );
    console.log("Res");
    console.log(res);
    return {
      status: "307",
      statusDescription: "Temporary Redirect",
      headers: {
        location: [
          {
            key: "location",
            value: redirectedFromUri,
          },
        ],
        "set-cookie": getCookieHeaders(
          clientId,
          oauthScopes,
          res.data,
          domainName,
          cookieSettings,
        ),
        ...cloudFrontHeaders,
      },
    };
  } catch (err) {
    console.log("BAD REQUEST");
    return {
      body: createErrorHtml("Bad Request", err.toString(), redirectedFromUri),

      status: "400", // Note: do not send 403 (!) as we have CloudFront send back index.html for 403's to enable SPA-routing
      headers: {
        ...cloudFrontHeaders,
        "content-type": [
          {
            key: "Content-Type",
            value: "text/html; charset=UTF-8",
          },
        ],
      },
    };
  }
};
