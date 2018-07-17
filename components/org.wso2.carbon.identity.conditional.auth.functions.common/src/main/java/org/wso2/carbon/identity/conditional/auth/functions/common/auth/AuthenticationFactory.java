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

package org.wso2.carbon.identity.conditional.auth.functions.common.auth;

/**
 * Factory to get authentication manager.
 */
public class AuthenticationFactory {

    /**
     * Get the authentication manager
     * @param authType authentication type.
     * @return Authentication manager.
     */
    public AuthenticationManager getAuthenticationManager(String authType){
        if ("Basic".equalsIgnoreCase(authType)) {
            return new BasicAuthenticationManager();
        } else {
            throw new IllegalArgumentException("Unsupported Authentication type.");
        }
    }
}
