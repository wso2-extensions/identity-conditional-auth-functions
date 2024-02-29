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
import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.exception.session.mgt.SessionManagementException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.conditional.auth.functions.user.exception.UserSessionTerminationException;
import org.wso2.carbon.identity.conditional.auth.functions.user.internal.UserFunctionsServiceHolder;
import org.wso2.carbon.user.core.UserRealm;

/**
 * Function to terminate the specified user's session with specified sessionId.
 */
public class TerminateUserSessionImpl implements TerminateUserSession {

    private static final Log LOG = LogFactory.getLog(TerminateUserSession.class);

    @Override
    @HostAccess.Export
    public boolean terminateUserSession(JsAuthenticatedUser user, String sessionId) {

        try {
            return terminateUserSession(user.getWrapped(), sessionId);
        } catch (UserSessionTerminationException e) {
            LOG.error("Error occurred while terminating user session: " + sessionId, e);
            return false;
        }
    }

    private boolean terminateUserSession(AuthenticatedUser authenticatedUser, String sessionId)
            throws UserSessionTerminationException {

        boolean result = false;
        String tenantDomain = authenticatedUser.getTenantDomain();
        String username = authenticatedUser.getUserName();

        try {
            UserRealm userRealm = Utils.getUserRealm(tenantDomain);
            if (userRealm != null) {
                String userId = authenticatedUser.getUserId();
                result = UserFunctionsServiceHolder.getInstance()
                        .getUserSessionManagementService().terminateSessionBySessionId(userId, sessionId);
            }
            if (result && LOG.isDebugEnabled()) {
                LOG.debug("Session: " + sessionId + " of user: " + username + " terminated");
            }
        } catch (FrameworkException e) {
            throw new UserSessionTerminationException("Error in evaluating the function ", e);
        } catch (SessionManagementException e) {
            throw new UserSessionTerminationException
                    ("Error occurred while terminating the user session for sessionId: " + sessionId, e);
        } catch (UserIdNotFoundException e) {
            throw new UserSessionTerminationException
                    ("Error occurred while retrieving the UserID for user: " + username, e);
        }
        return result;
    }

}
