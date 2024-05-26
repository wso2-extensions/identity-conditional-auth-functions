/*
 * Copyright (c) 2018, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicNameValuePair;
import org.graalvm.polyglot.HostAccess;
import org.json.simple.JSONObject;
import org.wso2.carbon.identity.conditional.auth.functions.http.util.AuthConfigModel;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
    @HostAccess.Export
    public void httpPost(String endpointURL, Object... params) {

        Map<String, Object> eventHandlers;
        Map<String, Object> payloadData = new HashMap<>();
        Map<String, String> headers = new HashMap<>();
        AuthConfigModel authConfig = null;

        switch (params.length) {
            case 1:
                if (params[0] instanceof Map) {
                    eventHandlers = (Map<String, Object>) params[0];
                } else {
                    throw new IllegalArgumentException("Invalid argument type. Expected eventHandlers " +
                            "(Map<String, Object>).");
                }
                break;
            case 2:
                if (params[0] instanceof Map && params[1] instanceof Map) {
                    payloadData = (Map<String, Object>) params[0];
                    eventHandlers = (Map<String, Object>) params[1];
                }  else {
                    throw new IllegalArgumentException("Invalid argument types. Expected payloadData and eventHandlers " +
                            "(both of type Map<String, Object>) respectively.");
                }
                break;
            case 3:
                if (params[0] instanceof Map && params[1] instanceof Map && params[2] instanceof Map) {
                    payloadData = (Map<String, Object>) params[0];
                    headers = validateHeaders((Map<String, ?>) params[1]);
                    eventHandlers = (Map<String, Object>) params[2];
                }  else {
                    throw new IllegalArgumentException("Invalid argument type. Expected payloadData " +
                            "(Map<String, Object>), headers (Map<String, String>), and eventHandlers " +
                            "(Map<String, Object>) respectively.");
                }
                break;
            case 4:
                if (params[0] instanceof Map && params[1] instanceof Map && params[2] instanceof Map && params[3] instanceof Map) {
                    payloadData = (Map<String, Object>) params[0];
                    headers = validateHeaders((Map<String, ?>) params[1]);
                    authConfig = getAuthConfigModel((Map<String, Object>) params[2]);
                    eventHandlers = (Map<String, Object>) params[3];
                }  else {
                    throw new IllegalArgumentException("Invalid argument type. Expected payloadData " +
                            "(Map<String, Object>), headers (Map<String, String>), authConfig (Map<String, String>)," +
                            " and eventHandlers (Map<String, Object>) respectively.");
                }
                break;
            default:
                throw new IllegalArgumentException("Invalid number of arguments. Expected 1, 2, 3, or 4. Found: "
                        + params.length + ".");
        }

        HttpPost request = new HttpPost(endpointURL);
        headers.putIfAbsent(CONTENT_TYPE, TYPE_APPLICATION_JSON);
        setHeaders(request, headers);

        if (MapUtils.isNotEmpty(payloadData)) {
            /*
            For the header "Content-Type : application/x-www-form-urlencoded" request body data is set to
            UrlEncodedFormEntity format. For the other cases request body data is set to StringEntity format.
             */
            if (TYPE_APPLICATION_FORM_URLENCODED.equals(headers.get(CONTENT_TYPE))) {
                List<NameValuePair> entities = new ArrayList<>();
                for (Map.Entry<String, Object> dataElements : payloadData.entrySet()) {
                    String value = (dataElements.getValue() != null) ? dataElements.getValue().toString() : null;
                    entities.add(new BasicNameValuePair(dataElements.getKey(), value));
                }
                request.setEntity(new UrlEncodedFormEntity(entities, StandardCharsets.UTF_8));
            } else {
                JSONObject jsonObject = new JSONObject();
                jsonObject.putAll(payloadData);
                request.setEntity(new StringEntity(jsonObject.toJSONString(), StandardCharsets.UTF_8));
            }
        }

        executeHttpMethod(request, eventHandlers, authConfig);
    }
}
