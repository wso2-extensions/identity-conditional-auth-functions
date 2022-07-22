/*
 * Copyright (c) 2022, WSO2 LLC. (http://www.wso2.com).
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;

import java.util.ArrayList;
import java.util.List;

public class GetAuthenticatedAppsFuncImp implements GetAuthenticatedApplicationsFunction {

    private static final Log log = LogFactory.getLog(GetAuthenticatedAppsFuncImp.class);

    /**
     * Retrieve the already authenticated applications for a given session.
     *
     * @param context context object.
     * @return List of already authenticated applications' name of the given session.
     */
    @Override
    public List<String> getAuthenticatedApplications(JsAuthenticationContext context) {

        String sessionContextKey = context.getWrapped().getSessionIdentifier();
        List<String> authenticatedApps = new ArrayList<>();
        if (sessionContextKey != null) {
            SessionContext sessionContext = FrameworkUtils.getSessionContextFromCache(sessionContextKey,
                    context.getWrapped().getLoginTenantDomain());
            authenticatedApps = sessionContext.getAuthenticatedIdPsOfApp();
        }
        return authenticatedApps;
    }
}
