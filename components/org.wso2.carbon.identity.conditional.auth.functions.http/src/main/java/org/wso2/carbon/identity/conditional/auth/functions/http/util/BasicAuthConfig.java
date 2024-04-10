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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/**
 * Implementation of the {@link AuthConfig}
 * This class is used to configure the basic authentication.
 * The username and password are added to the request header.
 */
public class BasicAuthConfig implements AuthConfig {
    private String username;
    private String password;
    private static final String USERNAME_VARIABLE_NAME = "username";
    private static final String PASSWORD_VARIABLE_NAME = "password";

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    @Override
    public HttpUriRequest applyAuth(HttpUriRequest request, AuthConfigModel authConfigModel) {

        Map<String, Object> properties = authConfigModel.getProperties();
        setUsername(properties.get(USERNAME_VARIABLE_NAME).toString());
        setPassword(properties.get(PASSWORD_VARIABLE_NAME).toString());
        String auth = getUsername() + ":" + getPassword();
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));
        request.addHeader("Authorization", "Basic " + encodedAuth);

        return request;
    }
}
