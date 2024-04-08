/*
 *  Copyright (c) 2024, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.wso2.carbon.identity.conditional.auth.functions.http.util;

import org.apache.http.client.methods.HttpUriRequest;
import org.wso2.carbon.identity.secret.mgt.core.exception.SecretManagementException;

import java.util.Map;

import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.CommonUtils.*;

/**
 * Implementation of the {@link AuthConfig}
 * This class is used to configure the bearer token authentication.
 * The bearer token is added to the request header.
 */
public class BearerTokenAuthConfig implements AuthConfig {
    private String token;

    public void setToken(String token) throws SecretManagementException {
        this.token = getResolvedSecret(token);
    }

    public String getToken() {
        return token;
    }

    @Override
    public HttpUriRequest applyAuth(HttpUriRequest request, AuthConfigModel authConfigModel)
            throws SecretManagementException {

        Map<String, Object> properties = authConfigModel.getProperties();
        setToken(properties.get("token").toString());
        request.setHeader("Authorization", "Bearer " + getToken());
        return request;
    }
}
