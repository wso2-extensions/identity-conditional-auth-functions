/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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
package org.wso2.carbon.identity.conditional.auth.functions.http.util;

import org.apache.http.client.methods.HttpUriRequest;

import java.util.Map;

/**
 * Implementation of the {@link AuthConfig}
 * This class is used to configure the API key authentication.
 * The API key is added to the request header.
 */
public class ApiKeyAuthConfig implements AuthConfig {
    private String headerName = "X-API-KEY"; // Default header name
    private String apiKey;
    private static final String HEADER_NAME_VARIABLE_NAME = "headerName";
    private static final String API_KEY_VARIABLE_NAME = "apiKey";

    public void setHeaderName(String headerName) {
        this.headerName = headerName;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public String getHeaderName() {
        return headerName;
    }

    public String getApiKey() {
        return apiKey;
    }

    @Override
    public HttpUriRequest applyAuth(HttpUriRequest request, AuthConfigModel authConfigModel) {

        Map<String, Object> properties = authConfigModel.getProperties();
        setApiKey(properties.get(API_KEY_VARIABLE_NAME).toString());
        setHeaderName(properties.get(HEADER_NAME_VARIABLE_NAME).toString());
        request.addHeader(getHeaderName(), getApiKey());
        return request;
    }
}
