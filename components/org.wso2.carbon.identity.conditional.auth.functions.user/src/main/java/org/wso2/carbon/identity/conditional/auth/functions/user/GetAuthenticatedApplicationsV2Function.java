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

package org.wso2.carbon.identity.conditional.auth.functions.user;

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.conditional.auth.functions.user.model.JsApplication;

import java.util.List;

/**
 * Function definition for retrieving authenticated applications.
 */
@FunctionalInterface
public interface GetAuthenticatedApplicationsV2Function {

    /**
     * Retrieve the already authenticated applications for a given session.
     *
     * @param context context object.
     * @return List of already authenticated applications of the given session.
     */
    List<JsApplication> getAuthenticatedApplications(JsAuthenticationContext context);
}
