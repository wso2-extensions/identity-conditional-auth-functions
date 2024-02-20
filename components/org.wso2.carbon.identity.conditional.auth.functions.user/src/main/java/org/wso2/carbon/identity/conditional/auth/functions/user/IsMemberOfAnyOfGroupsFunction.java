/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.base.JsBaseAuthenticatedUser;

import java.util.List;

/**
 * Function to check if the given user is a member in at least one of the given groups.
 * The purpose is to perform dynamic authentication selection based on user groups.
 */
@FunctionalInterface
public interface IsMemberOfAnyOfGroupsFunction {

    /**
     * Checks if the given user is a member in one of the given group names.
     *
     * @param user       Authenticated user.
     * @param groupNames Groups to be checked.
     * @return True if the user is a member in at least one of the given groups.
     */
    boolean isMemberOfAnyOfGroups(JsBaseAuthenticatedUser user, List<String> groupNames);
}
