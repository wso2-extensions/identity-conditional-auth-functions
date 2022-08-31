/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.apache.http.HttpHeaders.ACCEPT;
import static org.apache.http.HttpHeaders.CONTENT_TYPE;


/**
 * Implementation of the {@link HTTPPostFunction}
 */
public class HTTPPostFunctionImpl extends AbstractHTTPFunction implements HTTPPostFunction {

    private static final Log LOG = LogFactory.getLog(HTTPPostFunctionImpl.class);

    public HTTPPostFunctionImpl() {

       super();
    }

    @Override
    public void httpPost(String epUrl, Object... params) {

        Map<String, Object> eventHandlers = new HashMap<>();
        Map<String, Object> payloadData = new HashMap<>();
        Map<String, String> headers = new HashMap<>();

        if (params.length == 2) {
            if (params[0] instanceof  Map && params[1] instanceof Map) {
                payloadData = (Map<String, Object>) params[0];
                eventHandlers = (Map<String, Object>) params[1];
            }
        } else if (params.length == 3) {
            if (params[0] instanceof  Map) {
                payloadData = (Map<String, Object>) params[0];
            }
            if (params[1] instanceof  Map) {
                headers = (Map<String, String>) params[1];
            }
            if (params[2] instanceof Map) {
                eventHandlers = (Map<String, Object>) params[2];
            }
        }

        HttpPost request = new HttpPost(epUrl);
        if (headers != null) {
            // Check if the "Content-Type" is in headers map else set APPLICATION_JSON as default "Content-Type".
            if (!headers.containsKey(CONTENT_TYPE)){
                request.setHeader(CONTENT_TYPE, TYPE_APPLICATION_JSON);
            }
            for (Map.Entry<String, String> dataElements : headers.entrySet()) {
                request.setHeader(dataElements.getKey(), dataElements.getValue());
            }
        } else {
            // If no headers were given, set Content-Type to "application/json".
            request.setHeader(CONTENT_TYPE, TYPE_APPLICATION_JSON);
        }
        request.setHeader(ACCEPT, TYPE_APPLICATION_JSON);

        /*
          For the header "Content-Type : application/x-www-form-urlencoded"
          request body data is set to UrlEncodedFormEntity format.
         */
        if (headers != null && TYPE_APPLICATION_FORM_URLENCODED.equals(headers.get(CONTENT_TYPE))) {
            List<NameValuePair> entities = new ArrayList<NameValuePair>();
            for (Map.Entry<String, Object> dataElements : payloadData.entrySet()) {
                entities.add(new BasicNameValuePair(dataElements.getKey(), (String) dataElements.getValue()));
            }
            request.setEntity(new UrlEncodedFormEntity(entities, StandardCharsets.UTF_8));
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
