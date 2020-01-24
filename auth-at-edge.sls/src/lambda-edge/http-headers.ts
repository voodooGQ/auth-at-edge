// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import { CloudFrontResponseHandler, CloudFrontHeaders } from "aws-lambda";
import { getConfig, asCloudFrontHeaders, HttpHeaders } from "./shared";

export const handler: CloudFrontResponseHandler = async event => {
  const config = await getConfig();
  const headers = config.httpHeaders as HttpHeaders;
  const configuredHeaders: CloudFrontHeaders = asCloudFrontHeaders(headers);
  const resp = event.Records[0].cf.response;

  Object.assign(resp.headers, configuredHeaders);

  return resp;
};
