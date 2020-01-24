// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import { CloudFrontHeaders } from "aws-lambda";
import { SSM } from "aws-sdk";
import { parse } from "cookie";
import axios, { AxiosRequestConfig, AxiosResponse } from "axios";
import { Agent } from "https";
import { GetParameterResult } from "aws-sdk/clients/ssm";

export interface CookieSettings {
  idToken: string;
  accessToken: string;
  refreshToken: string;
  nonce: string;
}

export interface HttpHeaders {
  [key: string]: string;
}

interface ConfigFromDisk {
  userPoolId: string;
  clientId: string;
  oauthScopes: string[];
  cognitoAuthDomain: string;
  redirectPathSignIn: string;
  redirectPathSignOut: string;
  redirectPathAuthRefresh: string;
  cookieSettings: CookieSettings;
  httpHeaders: HttpHeaders;
}

export interface Config extends ConfigFromDisk {
  tokenIssuer: string;
  tokenJwksUri: string;
  cloudFrontHeaders: CloudFrontHeaders;
}

// @TODO: Defaulting to us-east-1 for POC. Will need to introduce a replicator
// for the ssm parameters in a production version as no way to pass the
// region where the values are stored.
const ssm = new SSM({ region: "us-east-1" });
// @TODO: https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-throughput.html <-- Increase throughput possibly
export async function getParameterValue(
  parameterName: string,
): Promise<string> {
  console.log("IN GET_PARAMETER_VALUE");
  const r: GetParameterResult = await ssm
    .getParameter({ Name: parameterName })
    .promise();
  console.log(r);

  if (!r.Parameter || !r.Parameter.Value) {
    const msg = `Could not retrieve a value for the ${parameterName} parameter`;
    console.log(msg);
    throw new Error(msg);
  }
  console.log("END GET_PARAMETER_VALUE");
  return r.Parameter.Value;
}

export async function getConfig(): Promise<any> {
  console.log("IN GETCONFIG");

  const config = {
    clientId: await getParameterValue("client-id"),
    oauthScopes: [
      "phone",
      "email",
      "profile",
      "openid",
      "aws.cognito.signin.user.admin",
    ],
    cognitoAuthDomain: await getParameterValue("cognito-auth-domain"),
    userPoolId: await getParameterValue("user-pool-id"),
    redirectPathSignIn: "/parseauth",
    redirectPathAuthRefresh: "/refreshauth",
    redirectPathSignOut: "/signout",
    httpHeaders: {
      "Content-Security-Policy":
        "default-src 'none'; img-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; connect-src 'self' https://*.amazonaws.com https://*.amazoncognito.com",
      "Strict-Transport-Security":
        "max-age=31536000; includeSubdomains; preload",
      "Referrer-Policy": "same-origin",
      "X-XSS-Protection": "1; mode=block",
      "X-Frame-Options": "DENY",
      "X-Content-Type-Options": "nosniff",
    },
    cookieSettings: {
      idToken: "Path=/; Secure; SameSite=Lax",
      accessToken: "Path=/; Secure; SameSite=Lax",
      refreshToken: "Path=/; Secure; SameSite=Lax",
      nonce: "Path=/; Secure; HttpOnly; Max-Age=1800; SameSite=Lax",
    },
  };
  console.log("Config");
  console.log(config);

  // Derive the issuer and JWKS uri all JWT's will be signed with from the User Pool's ID and region:
  const userPoolRegion = config.userPoolId.match(/^(\S+?)_\S+$/)![1];
  console.log("UserPoolRegion");
  console.log(userPoolRegion);
  const tokenIssuer = `https://cognito-idp.${userPoolRegion}.amazonaws.com/${config.userPoolId}`;
  console.log("tokenIssuer");
  console.log(tokenIssuer);
  const tokenJwksUri = `${tokenIssuer}/.well-known/jwks.json`;
  console.log("tokenJwksUri");
  console.log(tokenJwksUri);

  console.log("END GETCONFIG");
  return Promise.resolve({
    ...config,
    tokenIssuer,
    tokenJwksUri,
    cloudFrontHeaders: asCloudFrontHeaders(config.httpHeaders),
  });
}

type Cookies = { [key: string]: string };

function extractCookiesFromHeaders(headers: CloudFrontHeaders) {
  console.log("IN EXTRACTCOOKIESFROMHEADERS");
  console.log("headers.cookie");
  console.log(headers["cookie"]);
  // Cookies are present in the HTTP header "Cookie" that may be present multiple times.
  // This utility function parses occurrences  of that header and splits out all the cookies and their values
  // A simple object is returned that allows easy access by cookie name: e.g. cookies["nonce"]
  if (!headers["cookie"]) {
    return {};
  }
  const cookies = headers["cookie"].reduce(
    (reduced, header) => Object.assign(reduced, parse(header.value)),
    {} as Cookies,
  );

  return cookies;
}

function withCookieDomain(
  distributionDomainName: string,
  cookieSettings: string,
) {
  if (cookieSettings.toLowerCase().indexOf("domain") === -1) {
    // Add leading dot for compatibility with Amplify (or js-cookie really)
    return `${cookieSettings}; Domain=.${distributionDomainName}`;
  }
  return cookieSettings;
}

export function asCloudFrontHeaders(headers: HttpHeaders): CloudFrontHeaders {
  return Object.entries(headers).reduce(
    (reduced, [key, value]) =>
      Object.assign(reduced, {
        [key.toLowerCase()]: [
          {
            key,
            value,
          },
        ],
      }),
    {} as CloudFrontHeaders,
  );
}

export function extractAndParseCookies(
  headers: CloudFrontHeaders,
  clientId: string,
) {
  console.log("IN EXTRACTANDPARSECOOKIES");
  const cookies = extractCookiesFromHeaders(headers);
  console.log("Cookies");
  console.log(cookies);
  if (!cookies) {
    return {};
  }

  const keyPrefix = `CognitoIdentityServiceProvider.${clientId}`;
  const lastUserKey = `${keyPrefix}.LastAuthUser`;
  const tokenUserName = cookies[lastUserKey];

  const scopeKey = `${keyPrefix}.${tokenUserName}.tokenScopesString`;
  const scopes = cookies[scopeKey];

  const idTokenKey = `${keyPrefix}.${tokenUserName}.idToken`;
  const idToken = cookies[idTokenKey];

  const accessTokenKey = `${keyPrefix}.${tokenUserName}.accessToken`;
  const accessToken = cookies[accessTokenKey];

  const refreshTokenKey = `${keyPrefix}.${tokenUserName}.refreshToken`;
  const refreshToken = cookies[refreshTokenKey];

  return {
    tokenUserName,
    idToken,
    accessToken,
    refreshToken,
    scopes,
    nonce: cookies["spa-auth-edge-nonce"],
    pkce: cookies["spa-auth-edge-pkce"],
  };
}

export function decodeToken(jwt: string) {
  const tokenBody = jwt.split(".")[1];
  const decodableTokenBody = tokenBody.replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(Buffer.from(decodableTokenBody, "base64").toString());
}

export function getCookieHeaders(
  clientId: string,
  oauthScopes: string[],
  tokens: { id_token: string; access_token: string; refresh_token?: string },
  domainName: string,
  cookieSettings: CookieSettings,
  expireAllTokens = false,
) {
  // Set cookies with the exact names and values Amplify uses for seamless interoperability with Amplify
  const decodedIdToken = decodeToken(tokens.id_token);
  const tokenUserName = decodedIdToken["cognito:username"];
  const keyPrefix = `CognitoIdentityServiceProvider.${clientId}`;
  const idTokenKey = `${keyPrefix}.${tokenUserName}.idToken`;
  const accessTokenKey = `${keyPrefix}.${tokenUserName}.accessToken`;
  const refreshTokenKey = `${keyPrefix}.${tokenUserName}.refreshToken`;
  const lastUserKey = `${keyPrefix}.LastAuthUser`;
  const scopeKey = `${keyPrefix}.${tokenUserName}.tokenScopesString`;
  const scopesString = oauthScopes.join(" ");
  const userDataKey = `${keyPrefix}.${tokenUserName}.userData`;
  const userData = JSON.stringify({
    UserAttributes: [
      {
        Name: "sub",
        Value: decodedIdToken["sub"],
      },
      {
        Name: "email",
        Value: decodedIdToken["email"],
      },
    ],
    Username: tokenUserName,
  });

  const cookies = {
    [idTokenKey]: `${tokens.id_token}; ${withCookieDomain(
      domainName,
      cookieSettings.idToken,
    )}`,
    [accessTokenKey]: `${tokens.access_token}; ${withCookieDomain(
      domainName,
      cookieSettings.accessToken,
    )}`,
    [refreshTokenKey]: `${tokens.refresh_token}; ${withCookieDomain(
      domainName,
      cookieSettings.refreshToken,
    )}`,
    [lastUserKey]: `${tokenUserName}; ${withCookieDomain(
      domainName,
      cookieSettings.idToken,
    )}`,
    [scopeKey]: `${scopesString}; ${withCookieDomain(
      domainName,
      cookieSettings.accessToken,
    )}`,
    [userDataKey]: `${encodeURIComponent(userData)}; ${withCookieDomain(
      domainName,
      cookieSettings.idToken,
    )}`,
    "amplify-signin-with-hostedUI": `true; ${withCookieDomain(
      domainName,
      cookieSettings.accessToken,
    )}`,
  };

  // Expire cookies if needed
  if (expireAllTokens) {
    Object.keys(cookies).forEach(
      key => (cookies[key] = expireCookie(cookies[key])),
    );
  } else if (!tokens.refresh_token) {
    cookies[refreshTokenKey] = expireCookie(cookies[refreshTokenKey]);
  }

  // Return object in format of CloudFront headers
  return Object.entries(cookies).map(([k, v]) => ({
    key: "set-cookie",
    value: `${k}=${v}`,
  }));
}

function expireCookie(cookie: string) {
  const cookieParts = cookie
    .split(";")
    .map(part => part.trim())
    .filter(part => !part.toLowerCase().startsWith("max-age"))
    .filter(part => !part.toLowerCase().startsWith("expires"));
  const expires = `Expires=${new Date(0).toUTCString()}`;
  const [, ...settings] = cookieParts; // first part is the cookie value, which we'll clear
  return ["", ...settings, expires].join("; ");
}

const AXIOS_INSTANCE = axios.create({
  httpsAgent: new Agent({ keepAlive: true }),
});

export async function httpPostWithRetry(
  url: string,
  data: any,
  config: AxiosRequestConfig,
): Promise<AxiosResponse<any>> {
  let attempts = 0;
  while (++attempts) {
    try {
      return await AXIOS_INSTANCE.post(url, data, config);
    } catch (err) {
      console.error(`HTTP POST to ${url} failed (attempt ${attempts}):`);
      console.error((err.response && err.response.data) || err);
      if (attempts >= 5) {
        // Try 5 times at most
        break;
      }
      if (attempts >= 2) {
        // After attempting twice immediately, do some exponential backoff with jitter
        await new Promise(resolve =>
          setTimeout(
            resolve,
            25 * (Math.pow(2, attempts) + Math.random() * attempts),
          ),
        );
      }
    }
  }
  throw new Error(`HTTP POST to ${url} failed`);
}

export function createErrorHtml(
  title: string,
  message: string,
  tryAgainHref: string,
) {
  return `<!DOCTYPE html>
<html lang="en">
  <head>
      <meta charset="utf-8">
      <title>${title}</title>
  </head>
  <body>
      <h1>${title}</h1>
      <p><b>ERROR:</b> ${message}</p>
      <a href="${tryAgainHref}">Try again</a>
  </body>
</html>`;
}
