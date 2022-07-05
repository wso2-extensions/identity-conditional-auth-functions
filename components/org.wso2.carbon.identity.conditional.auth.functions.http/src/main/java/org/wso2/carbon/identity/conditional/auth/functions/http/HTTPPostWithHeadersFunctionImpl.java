/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.http;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicNameValuePair;
import org.json.simple.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.apache.http.HttpHeaders.ACCEPT;
import static org.apache.http.HttpHeaders.CONTENT_TYPE;

/**
 * Implementation of the {@link HTTPPostWithHeadersFunction}
 */
public class HTTPPostWithHeadersFunctionImpl extends AbstractHTTPFunction implements HTTPPostWithHeadersFunction {

    private static final Log LOG = LogFactory.getLog(HTTPPostWithHeadersFunctionImpl.class);

    public HTTPPostWithHeadersFunctionImpl() {

       super();
    }

    @Override
    public void httpPostWithHeaders(String epUrl, Map<String, Object> payloadData, Map<String, String>headers, Map<String, Object> eventHandlers) {

        HttpPost request = new HttpPost(epUrl);

        if (headers != null) {
            // Check if "Content-Type" is in headers map else set APPLICATION_JSON as default "Content-Type"
            if (!headers.containsKey(CONTENT_TYPE)){
                request.setHeader(CONTENT_TYPE, TYPE_APPLICATION_JSON);
            }

            // Add headers to the request
            for (Map.Entry<String, String> dataElements : headers.entrySet()) {
                request.setHeader(dataElements.getKey(), dataElements.getValue());
            }
        } else {
            // If no headers were given, set Content-Type to "application/json"
            request.setHeader(CONTENT_TYPE, TYPE_APPLICATION_JSON);
        }
        request.setHeader(ACCEPT, TYPE_APPLICATION_JSON);

        /*
          For the header Content-Type : application/x-www-form-urlencoded
          Request payload is sent as UrlEncodedFormEntity
          Else the payload is sent as Json
         */
        if (headers != null && TYPE_APPLICATION_FORM_URL_ENCODED.equals(headers.get(CONTENT_TYPE))) {

            List<NameValuePair> payload = new ArrayList<>();
            for (Map.Entry<String, Object> dataElements : payloadData.entrySet()) {
                payload.add(new BasicNameValuePair(dataElements.getKey(), (String) dataElements.getValue()));
            }
            request.setEntity(new UrlEncodedFormEntity(payload, StandardCharsets.UTF_8));
        } else {

            JSONObject jsonObject = new JSONObject();
            for (Map.Entry<String, Object> dataElements : payloadData.entrySet()) {
                jsonObject.put(dataElements.getKey(), dataElements.getValue());
            }
            request.setEntity(new StringEntity(jsonObject.toJSONString(), StandardCharsets.UTF_8));
        }

        executeHttpMethod(request, eventHandlers);
    }
}
