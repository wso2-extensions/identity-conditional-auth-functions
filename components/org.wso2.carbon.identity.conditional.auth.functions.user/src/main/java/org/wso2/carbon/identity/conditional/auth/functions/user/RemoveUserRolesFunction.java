/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import java.util.List;

/**
 * Function to remove given roles from the a given user.
 * The purpose is to perform role removing during dynamic authentication.
 */
@FunctionalInterface
public interface RemoveUserRolesFunction {

    /**
     * Remove roles for a given <code>user</code>
     *
     * @param user          Authenticated user.
     * @param removingRoles Roles to be removed.
     * @return <code>true</code> If the role assigning is successfully completed. <code>false</code> for any other case.
     */
    boolean removeUserRoles(JsAuthenticatedUser user, List<String> removingRoles);
}
