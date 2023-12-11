/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.conditional.auth.functions.user;

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;

import java.util.List;

/**
 * Function to remove given roles(v2) for a given user.
 * The purpose is to perform role(v2) removing during dynamic authentication.
 */
@FunctionalInterface
public interface RemoveUserRolesV2Function {

    /**
     * Remove roles for a given <code>user</code>
     *
     * @param context authentication context
     * @param roleListToRemove Roles to be removed.
     * @return <code>true</code> If the role removal is successfully completed. <code>false</code> for any other case.
     */
    boolean removeUserRolesV2(JsAuthenticationContext context, List<String> roleListToRemove);
}
