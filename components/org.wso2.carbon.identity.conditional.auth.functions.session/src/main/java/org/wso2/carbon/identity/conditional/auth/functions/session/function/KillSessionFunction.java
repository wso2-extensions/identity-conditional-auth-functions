/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */
package org.wso2.carbon.identity.conditional.auth.functions.session.function;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.services.SessionManagementService;
import org.wso2.carbon.identity.conditional.auth.functions.session.util.SessionValidationConstants;
import org.wso2.carbon.utils.xml.StringUtils;

import java.util.Map;

/**
 * Represents javascript function provided in conditional authentication to terminate a session with given sessionID.
 */
public class KillSessionFunction implements ExecuteActionFunction {

    private static final Log log = LogFactory.getLog(KillSessionFunction.class);

    @Override
    public boolean execute(JsAuthenticationContext context, Map<String, String> map) {

        String sessionId = map.get(SessionValidationConstants.TERMINATION_SESSION_ID);
        SessionManagementService sessionManagementService = new SessionManagementService();
        if (log.isDebugEnabled()) {
            log.debug("Session with session id :" + sessionId + " is requested to kill");
        }
        if ( StringUtils.isEmpty(sessionId) || sessionId.isEmpty()) {
            return false;
        }
        sessionManagementService.removeSession(sessionId);

        return true;
    }
}
