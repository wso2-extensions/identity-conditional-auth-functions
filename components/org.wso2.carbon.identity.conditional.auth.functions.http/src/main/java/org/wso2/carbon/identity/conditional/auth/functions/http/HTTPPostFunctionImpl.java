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

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
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

        if (StringUtils.isBlank(epUrl)) {
            LOG.error("Endpoint URL cannot be empty.");
            return;
        }

        switch (params.length) {
            case 1:
                if (params[0] instanceof Map) {
                    eventHandlers = (Map<String, Object>) params[0];
                } else {
                    LOG.error("Invalid parameter type.");
                    return;
                }
                break;
            case 2:
                if (params[0] instanceof Map && params[1] instanceof Map) {
                    payloadData = (Map<String, Object>) params[0];
                    eventHandlers = (Map<String, Object>) params[1];
                }  else {
                    LOG.error("Invalid parameter type.");
                    return;
                }
                break;
            case 3:
                if (params[0] instanceof Map && params[1] instanceof Map && params[2] instanceof Map) {
                    payloadData = (Map<String, Object>) params[0];
                    headers = (Map<String, String>) params[1];
                    eventHandlers = (Map<String, Object>) params[2];
                }  else {
                    LOG.error("Invalid parameter type.");
                    return;
                }
                break;
            default:
                LOG.error("Invalid number of parameters.");
                return;
        }

        HttpPost request = new HttpPost(epUrl);
        request.setHeader(ACCEPT, TYPE_APPLICATION_JSON);

        if (headers == null) {
            headers = new HashMap<>();
        }
        headers.putIfAbsent(CONTENT_TYPE, TYPE_APPLICATION_JSON);
        headers.forEach(request::setHeader);

        /*
          For the header "Content-Type : application/x-www-form-urlencoded"
          request body data is set to UrlEncodedFormEntity format.
         */
        if (MapUtils.isNotEmpty(payloadData)) {
            if (TYPE_APPLICATION_FORM_URLENCODED.equals(headers.get(CONTENT_TYPE))) {
                List<NameValuePair> entities = new ArrayList<NameValuePair>();
                for (Map.Entry<String, Object> dataElements : payloadData.entrySet()) {
                    entities.add(new BasicNameValuePair(dataElements.getKey(), dataElements.getValue().toString()));
                }
                request.setEntity(new UrlEncodedFormEntity(entities, StandardCharsets.UTF_8));
            } else {
                JSONObject jsonObject = new JSONObject();
                for (Map.Entry<String, Object> dataElements : payloadData.entrySet()) {
                    jsonObject.put(dataElements.getKey(), dataElements.getValue());
                }
                request.setEntity(new StringEntity(jsonObject.toJSONString(), StandardCharsets.UTF_8));
            }
        }
        executeHttpMethod(request, eventHandlers);
    }
}
