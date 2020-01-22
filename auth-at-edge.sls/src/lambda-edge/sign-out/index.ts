// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import { stringify as stringifyQueryString } from "querystring";
import { CloudFrontRequestHandler } from "aws-lambda";
import {
  getConfig,
  extractAndParseCookies,
  getCookieHeaders,
} from "../shared/shared";

const {
  clientId,
  oauthScopes,
  cognitoAuthDomain,
  cookieSettings,
  cloudFrontHeaders,
  redirectPathSignOut,
} = getConfig();

export const handler: CloudFrontRequestHandler = async event => {
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
    cookieSettings,
    cloudFrontHeaders,
    redirectPathSignOut,
  } = getConfig(origin.customHeaders);
  const domainName = request.headers["host"][0].value;
  const { idToken, accessToken, refreshToken } = extractAndParseCookies(
    request.headers,
    clientId,
  );
  console.log('IDToken');
  console.log(idToken);
  console.log('AccessToken');
  console.log(accessToken);
  console.log('RefreshToken');
  console.log(refreshToken);

  if (!idToken) {
    return {
      body: "Bad Request",
      status: "400", // Note: do not send 403 (!) as we have CloudFront send back index.html for 403's to enable SPA-routing
      statusDescription: "Bad Request",
      headers: cloudFrontHeaders,
    };
  }

  let tokens = {
    id_token: idToken!,
    access_token: accessToken!,
    refresh_token: refreshToken,
  };
  const qs = {
    logout_uri: `https://${domainName}${redirectPathSignOut}`,
    client_id: clientId,
  };

  return {
    status: "307",
    statusDescription: "Temporary Redirect",
    headers: {
      location: [
        {
          key: "location",
          value: `https://${cognitoAuthDomain}/logout?${stringifyQueryString(
            qs,
          )}`,
        },
      ],
      "set-cookie": getCookieHeaders(
        clientId,
        oauthScopes,
        tokens,
        domainName,
        cookieSettings,
        true,
      ),
      ...cloudFrontHeaders,
    },
  };
};
