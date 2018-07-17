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
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.conditional.auth.functions.session.exception.SessionValidationException;
import org.wso2.carbon.identity.conditional.auth.functions.session.model.Session;
import org.wso2.carbon.identity.conditional.auth.functions.session.util.SessionValidationUtil;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents javascript function provided in conditional authentication to retrieve active session data for given user.
 * The purpose is to perform dynamic authentication selection based on the active session count.
 */
public class GetSessionDataFunction implements GetUserSessionDataFunction {

    private static final Log log = LogFactory.getLog(GetSessionDataFunction.class);

    @Override
    public Map<String, Session> getData(JsAuthenticationContext context, Map<String, String> map) throws
            AuthenticationFailedException {

        Map<String, Session> sessionMap = new HashMap<>();
        AuthenticatedUser authenticatedUser = context.getWrapped().getLastAuthenticatedUser();
        if (authenticatedUser == null) {
            if (log.isDebugEnabled()) {
                log.debug("Unable to find the authenticated user from the Authentication context.");
            }
            throw new AuthenticationFailedException("Authentication user not found");
        }
        try {
            List<Session> sessionList = SessionValidationUtil.getSessionDetails(authenticatedUser);
            for (Session session : sessionList) {
                sessionMap.put(session.getSessionId(), session);
            }

        } catch (IOException | SessionValidationException e) {
            log.error("Failed to retrieve active session details", e);
        }
        return sessionMap;
    }
}
