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
 * Function to check if the given user has at least one of the given roles(v2).
 * The purpose is to perform dynamic authentication selection based on user role(v2).
 */
@FunctionalInterface
public interface HasAnyOfTheRolesV2Function {

    /**
     * Check if the user in the authentication context has any of the given roles.
     *
     * @param context authentication context
     * @param roleNames Role to be checked
     * @return <code>true</code> if the user has at least one of the  given roles. <code>false</code> for any other
     * case.
     */
    boolean hasAnyOfTheRolesV2(JsAuthenticationContext context, List<String> roleNames);
}
