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

import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.conditional.auth.functions.user.model.JsApplication;
import org.wso2.carbon.identity.conditional.auth.functions.user.model.JsWrapperFactoryProvider;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Function for retrieving javascript authenticated applications for a given session.
 */
public class GetAuthenticatedApplicationsV2FunctionImpl implements GetAuthenticatedApplicationsV2Function {

    @Override
    @HostAccess.Export
    public List<JsApplication> getAuthenticatedApplications(JsAuthenticationContext context) {

        return new GetAuthenticatedAppsFuncImp().getAuthenticatedApplications(context)
                .stream()
                .map(app -> JsWrapperFactoryProvider.getInstance().getWrapperFactory().createJsApplication(app))
                .collect(Collectors.toList());
    }
}
