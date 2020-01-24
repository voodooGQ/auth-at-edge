import { HttpHeaders } from "./../shared/shared";
// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import { CloudFrontResponseHandler, CloudFrontHeaders } from "aws-lambda";
import { getConfig, asCloudFrontHeaders } from "../shared/shared";

export const handler: CloudFrontResponseHandler = async event => {
  const config = await getConfig();
  const headers = config.httpHeaders as HttpHeaders;
  const configuredHeaders: CloudFrontHeaders = asCloudFrontHeaders(headers);
  console.log("configuredHeaders");
  console.log(configuredHeaders);
  const resp = event.Records[0].cf.response;
  console.log("http-headers handler");
  console.log("event");
  console.log(event);
  console.log("event.Records");
  console.log(event.Records);
  console.log("event.Records[0]");
  console.log(event.Records[0]);
  console.log("event.Records[0].cf");
  console.log(event.Records[0].cf);
  console.log("event.Records[0].cf.response");
  console.log(resp);
  console.log("event.Records[0].cf.response.headers");
  console.log(resp.headers);
  Object.assign(resp.headers, configuredHeaders);
  return resp;
};
