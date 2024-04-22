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

import org.wso2.carbon.identity.application.authentication.framework.AsyncReturn;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;

/**
 * Factory class to create the authentication configurations.
 * This class is used to create the authentication configurations based on the authentication type.
 * The supported authentication types are:
 * 1. ClientCredential
 * 2. BearerToken
 * 3. ApiKey
 * 4. BasicAuth
 */
public class AuthConfigFactory {

    /**
     * Create the authentication configuration based on the authentication type.
     *
     * @param authConfigModel       Authentication configuration model
     * @param authenticationContext Authentication context
     * @param asyncReturn           AsyncReturn
     * @return AuthConfig
     */
    public static AuthConfig getAuthConfig(AuthConfigModel authConfigModel,
                                           AuthenticationContext authenticationContext, AsyncReturn asyncReturn) {

        switch (authConfigModel.getType().toLowerCase()) {
            case "clientcredential":
                ClientCredentialAuthConfig clientCredentialAuthConfig = new ClientCredentialAuthConfig();
                clientCredentialAuthConfig.setAuthenticationContext(authenticationContext);
                clientCredentialAuthConfig.setAsyncReturn(asyncReturn);
                return clientCredentialAuthConfig;
            case "bearertoken":
                return new BearerTokenAuthConfig();
            case "apikey":
                return new ApiKeyAuthConfig();
            case "basicauth":
                return new BasicAuthConfig();
            default:
                throw new IllegalArgumentException("Unsupported authentication type: " + authConfigModel.getType());
        }
    }
}
