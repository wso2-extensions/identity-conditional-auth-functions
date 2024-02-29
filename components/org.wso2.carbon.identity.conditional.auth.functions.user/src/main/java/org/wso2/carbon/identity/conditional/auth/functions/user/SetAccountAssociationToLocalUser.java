/*
 *  Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.conditional.auth.functions.user;

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;

/**
 * Function to set associate local user to federated user.
 */
@FunctionalInterface
public interface SetAccountAssociationToLocalUser {

    /**
     * Set association to the local user with federated user.
     *
     * @param federatedUser       Federated user.
     * @param username            Local user's username.
     * @param tenantDomain        Tenant domain of the local user.
     * @param userStoreDomainName Userstore domain of the local user.
     * @return Whether the association is successful or not.
     */
    boolean doAssociationWithLocalUser(JsAuthenticatedUser federatedUser, String username, String tenantDomain,
                                       String userStoreDomainName);
}
