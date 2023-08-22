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
import org.wso2.carbon.identity.event.IdentityEventException;

import java.util.HashMap;
import java.util.Map;

import static org.apache.http.HttpHeaders.ACCEPT;

/**
 * Implementation of the {@link HTTPGetFunction}
 */
public class HTTPGetWithHeadersFunctionImpl extends AbstractHTTPFunction implements HTTPGetWithHeadersFunction {

    private static final Log LOG = LogFactory.getLog(HTTPGetWithHeadersFunctionImpl.class);

    public HTTPGetWithHeadersFunctionImpl() {

        super();
    }

    @Override
    public void httpGetWithHeaders(String epUrl, Map<String, String> headers, Map<String, Object> eventHandlers) {

        HttpGet request = new HttpGet(epUrl);

        if (headers == null) {
            headers = new HashMap<>();
        }
        headers.putIfAbsent(ACCEPT, TYPE_APPLICATION_JSON);
        headers.entrySet().stream()
                .filter(entry -> entry.getKey() != null)
                .forEach(entry -> request.setHeader(entry.getKey(), entry.getValue()));

        executeHttpMethod(request, eventHandlers);
    }
}