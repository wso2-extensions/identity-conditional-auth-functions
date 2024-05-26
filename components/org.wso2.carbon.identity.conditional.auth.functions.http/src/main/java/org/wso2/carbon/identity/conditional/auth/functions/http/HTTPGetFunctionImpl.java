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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.methods.HttpGet;
import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.conditional.auth.functions.http.util.AuthConfigModel;

import java.util.HashMap;
import java.util.Map;

/**
 * Implementation of the {@link HTTPGetFunction}
 */
public class HTTPGetFunctionImpl extends AbstractHTTPFunction implements HTTPGetFunction {

    private static final Log LOG = LogFactory.getLog(HTTPGetFunctionImpl.class);

    public HTTPGetFunctionImpl() {

        super();
    }

    @Override
    @HostAccess.Export
    public void httpGet(String endpointURL, Object... params) {

        Map<String, Object> eventHandlers;
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
                if (params[0] instanceof Map && params[1] instanceof Map ) {
                    headers = validateHeaders((Map<String, ?>) params[0]);
                    eventHandlers = (Map<String, Object>) params[1];
                } else {
                    throw new IllegalArgumentException("Invalid argument types. Expected headers (Map<String, String>) " +
                            "and eventHandlers (Map<String, Object>) respectively.");
                }
                break;
            case 3:
                if (params[0] instanceof Map && params[1] instanceof Map && params[2] instanceof Map) {
                    headers = validateHeaders((Map<String, ?>) params[0]);
                    authConfig = getAuthConfigModel((Map<String, Object>) params[1]);
                    eventHandlers = (Map<String, Object>) params[2];
                }  else {
                    throw new IllegalArgumentException("Invalid argument type. Expected " +
                            "headers (Map<String, String>), authConfig (Map<String, String>)," +
                            " and eventHandlers (Map<String, Object>) respectively.");
                }
                break;
            default:
                throw new IllegalArgumentException("Invalid number of arguments. Expected 1, 2 or 3, but got: " +
                        params.length + ".");
        }

        HttpGet request = new HttpGet(endpointURL);
        setHeaders(request, headers);

        executeHttpMethod(request, eventHandlers, authConfig);
    }
}
