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
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.conditional.auth.functions.session.exception.SessionValidationException;
import org.wso2.carbon.identity.conditional.auth.functions.session.model.Session;
import org.wso2.carbon.identity.conditional.auth.functions.session.util.SessionValidationConstants;
import org.wso2.carbon.identity.conditional.auth.functions.session.util.SessionValidationUtil;

import java.io.IOException;
import java.util.Map;

/**
 * Represents javascript function provided in conditional authentication to retrieve active session data for given user.
 * The purpose is to perform dynamic authentication selection based on the active session count.
 */
public class GetSessionDataFunction implements GetUserSessionDataFunction {

    private static final Log log = LogFactory.getLog(GetSessionDataFunction.class);

    @Override
    public JSONObject getData(JsAuthenticationContext context, Map<String, String> map) throws AuthenticationFailedException {

        JSONObject jsonObject = new JSONObject();
        JSONArray jsonArray = new JSONArray();
        AuthenticatedUser authenticatedUser = context.getWrapped().getLastAuthenticatedUser();
        if (authenticatedUser == null) {
            if (log.isDebugEnabled()) {
                log.debug("Unable to find the authenticated user from the Authentication context.");
            }
            throw new AuthenticationFailedException("Authentication user not found");
        }
        try {
            JSONArray sessionMetaData = SessionValidationUtil.getSessionDetails(authenticatedUser);
            for (int sessionIndex = 0; sessionIndex < sessionMetaData.length(); sessionIndex++) {
                JSONObject sessionJsonObject = sessionMetaData.getJSONObject(sessionIndex);
                JSONObject sessionValues = sessionJsonObject.getJSONObject(SessionValidationConstants.VALUE_TAG);
                String sessionId = sessionValues.getString(SessionValidationConstants.SESSION_ID_TAG);
                String timestamp = sessionJsonObject.get(SessionValidationConstants.TIMESTAMP_TAG).toString();
                String userAgent = sessionValues.get(SessionValidationConstants.USER_AGENT_TAG).toString();
                String ipAddress = sessionValues.getString(SessionValidationConstants.IP_TAG);
                String serviceProvider = sessionValues.getString(SessionValidationConstants.SERVICE_PROVIDER_TAG);
                Session session = new Session(sessionId, timestamp, userAgent, ipAddress, serviceProvider);
                jsonArray.put(session.getJSONObject());
            }
            jsonObject.put(SessionValidationConstants.SESSIONS_TAG, jsonArray);
        } catch (IOException | SessionValidationException e) {
            log.error("Failed to retrieve active session details",e);
        }
        return jsonObject;
    }
}
