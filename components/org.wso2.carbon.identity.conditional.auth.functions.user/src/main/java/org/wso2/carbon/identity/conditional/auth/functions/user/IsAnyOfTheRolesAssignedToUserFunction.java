/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.conditional.auth.functions.user;

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.base.JsBaseAuthenticatedUser;

import java.util.List;

/**
 * Function to check whether the specified user belongs to any of the specified roles.
 * Roles are directly retrieved from database without checking in the cache first.
 */
@FunctionalInterface
public interface IsAnyOfTheRolesAssignedToUserFunction {

    /**
     * Checks if the given <code>user</code> has the given <code>roleName</code>
     *
     * @param user      Authenticated user. Ideally from a given step.
     * @param roleNames Role to be checked
     * @return <code>true</code> if the user has at least one of the  given roles. <code>false</code> for any other
     * case.
     */
    boolean IsAnyOfTheRolesAssignedToUser(JsBaseAuthenticatedUser user, List<String> roleNames);
}
