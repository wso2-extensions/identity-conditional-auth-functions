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

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;

/**
 * Function to get active sessions and prompt to kill the sessions if the specified limit exceeds.
 */
@FunctionalInterface
public interface EnsureMaxSessionCountNotExceededForUserFunction {
    /**
     * Get active sessions and prompt to kill the sessions if the specified limit exceeds for a given <code>user</code>.
     *
     * @param user              Authenticated user.
     * @param maxSessionCount   Maximum number of active concurrent sessions.
     */
    void ensureMaxSessionCountNotExceededForUser(JsAuthenticatedUser user, int maxSessionCount);
}
