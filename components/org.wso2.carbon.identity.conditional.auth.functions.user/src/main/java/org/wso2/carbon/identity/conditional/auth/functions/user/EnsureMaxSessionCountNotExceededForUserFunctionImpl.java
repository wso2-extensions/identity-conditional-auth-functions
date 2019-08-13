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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsGraphBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.SerializableJsFunction;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserSessionException;
import org.wso2.carbon.identity.application.authentication.framework.exception.session.mgt.SessionManagementException;
import org.wso2.carbon.identity.application.authentication.framework.store.UserSessionStore;
import org.wso2.carbon.identity.conditional.auth.functions.user.internal.UserFunctionsServiceHolder;
import org.wso2.carbon.identity.conditional.auth.functions.user.model.UserAgent;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class EnsureMaxSessionCountNotExceededForUserFunctionImpl implements EnsureMaxSessionCountNotExceededForUserFunction {

    private static final Log LOG = LogFactory.getLog(EnsureMaxSessionCountNotExceededForUserFunctionImpl.class);

    @Override
    public void ensureMaxSessionCountNotExceededForUser(JsAuthenticatedUser user, int maxSessionCount) {
        List<String[]> sessionsForUser = null;
        Map<String, Object> data = null;
        Map<String, Object> handlers = null;
        String tenantDomain = user.getWrapped().getTenantDomain();
        String userStoreDomain = user.getWrapped().getUserStoreDomain();
        String username = user.getWrapped().getUserName();

        final String KILL_SESSIONS_FUNCTION[] =
                {"function (context) {",
                        "   var sessions = context.request.params.sessionsToKill;",
                        "   for (var key in sessions) {",
                        "       KillUserSession(context.currentKnownSubject, sessions[key]);",
                        "    }",
                        "}"};
        final String ABORT_LOGIN_FUNCTION[] =
                {"function(context) {",
                        "   sendError( '', {",
                        "                       'status': 'Login Aborted',",
                        "                       'statusMsg': 'Maximum limit of allowed concurrent active sessions exceeded.'",
                        "                   }",
                        "   );",
                        "}"};

        try {
            UserRealm userRealm = Utils.getUserRealm(user.getWrapped().getTenantDomain());
            if (userRealm != null) {
                UserStoreManager userStore = Utils.getUserStoreManager(tenantDomain, userRealm, userStoreDomain);
                if (userStore != null) {
                    String userId = UserSessionStore.getInstance().getUserId(username, Utils.getTenantId(tenantDomain), userStoreDomain);
                    sessionsForUser = UserFunctionsServiceHolder.getInstance()
                            .getUserSessionManagementService().getSessionsByUserId(userId).stream()
                            .map(userSession -> {
                                UserAgent userAgent = new UserAgent(userSession.getUserAgent());
                                return new String[]{
                                        userSession.getSessionId(),
                                        userSession.getLastAccessTime(),
                                        userAgent.getBrowser(),
                                        userAgent.getPlatform(),
                                        userAgent.getDevice()
                                };
                            })
                            .collect(Collectors.toList());
                }
            }
        } catch (SessionManagementException e) {
            LOG.error("Error occurred while retrieving sessions: ", e);
        } catch (FrameworkException e) {
            LOG.error("Error in evaluating the function ", e);
        } catch (UserSessionException e) {
            LOG.error("Error occurred while retrieving the UserID: ", e);
        }

        if (sessionsForUser.size() >= maxSessionCount) {
            data = new HashMap<>();
            handlers = new HashMap<>();

            data.put("maxSessionCount", maxSessionCount);
            data.put("sessions", sessionsForUser.toArray());
            handlers.put("onKillActiveSessions", new SerializableJsFunction(String.join(" ", KILL_SESSIONS_FUNCTION), true));
            handlers.put("onAbortLogin", new SerializableJsFunction(String.join(" ", ABORT_LOGIN_FUNCTION), true));

            JsGraphBuilder.getCurrentBuilder().addShowPrompt("multipleActiveSessions", data, handlers);
        }
    }
}
