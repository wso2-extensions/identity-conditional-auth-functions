/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.collections.MapUtils;
import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;

import java.util.Map;

public class CheckSessionExistenceFunctionImpl implements CheckSessionExistenceFunction {

    @Override
    @HostAccess.Export
    public boolean checkSessionExistence(int step, JsAuthenticationContext context) {

        StepConfig stepConfig = context.getWrapped()
                .getSequenceConfig().getAuthenticationGraph().getStepMap().get(step);
        Map<String, AuthenticatedIdPData> authenticatedIdPs = context.getWrapped().getCurrentAuthenticatedIdPs();

        // If there are no current authenticated IDPs, it means no authentication has been taken place yet.
        // So see whether there are previously authenticated IDPs for this session.
        // NOTE : currentAuthenticatedIdPs (if not null) always contains the previousAuthenticatedIdPs
        if (MapUtils.isEmpty(authenticatedIdPs)) {
            authenticatedIdPs = context.getWrapped().getPreviousAuthenticatedIdPs();
        }

        Map<String, AuthenticatorConfig> authenticatedStepIdps = FrameworkUtils
                .getAuthenticatedStepIdPs(stepConfig, authenticatedIdPs);

        return !authenticatedStepIdps.isEmpty();
    }
}
