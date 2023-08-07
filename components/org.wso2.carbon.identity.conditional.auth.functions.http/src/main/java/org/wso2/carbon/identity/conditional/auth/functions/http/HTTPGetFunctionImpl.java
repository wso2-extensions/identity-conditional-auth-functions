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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.methods.HttpGet;

import java.util.HashMap;
import java.util.Map;

import static org.apache.http.HttpHeaders.ACCEPT;

/**
 * Implementation of the {@link HTTPGetFunction}
 */
public class HTTPGetFunctionImpl extends AbstractHTTPFunction implements HTTPGetFunction {

    private static final Log LOG = LogFactory.getLog(HTTPGetFunctionImpl.class);

    public HTTPGetFunctionImpl() {

        super();
    }

    @Override
    public void httpGet(String epUrl, Object... params) {

        Map<String, Object> eventHandlers = new HashMap<>();
        Map<String, String> headers = new HashMap<>();

        if (StringUtils.isBlank(epUrl)) {
            LOG.error("Endpoint URL cannot be empty.");
            return;
        }

        try {
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
                    if (params[0] instanceof Map && params[1] instanceof Map ) {
                        headers = (Map<String, String>) params[0];
                        eventHandlers = (Map<String, Object>) params[1];
                    }  else {
                        LOG.error("Invalid parameter type.");
                        return;
                    }
                    break;
                default:
                    LOG.error("Invalid number of parameters.");
                    return;
            }

            HttpGet request = new HttpGet(epUrl);
            // Set default ACCEPT header to application/json
            request.setHeader(ACCEPT, TYPE_APPLICATION_JSON);

            headers.entrySet().stream()
                    .filter(entry -> entry.getKey() != null)
                    .forEach(entry -> request.setHeader(entry.getKey(), entry.getValue()));

            executeHttpMethod(request, eventHandlers);
        } catch (IllegalArgumentException e) {
            LOG.error("Invalid parameter type.", e);
        } catch (Exception e) {
            LOG.error("Error while executing http get.", e);
        }
    }
}
