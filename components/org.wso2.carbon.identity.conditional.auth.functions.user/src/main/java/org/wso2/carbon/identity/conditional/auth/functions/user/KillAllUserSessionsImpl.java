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
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserSessionException;
import org.wso2.carbon.identity.application.authentication.framework.exception.session.mgt.SessionManagementException;
import org.wso2.carbon.identity.application.authentication.framework.store.UserSessionStore;
import org.wso2.carbon.identity.conditional.auth.functions.user.internal.UserFunctionsServiceHolder;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;

public class KillAllUserSessionsImpl implements KillAllUserSessions {

    private static final Log LOG = LogFactory.getLog(KillAllUserSessions.class);

    @Override
    public boolean killUserSessions(JsAuthenticatedUser user) {
        boolean result = false;
        String tenantDomain = user.getWrapped().getTenantDomain();
        String userStoreDomain = user.getWrapped().getUserStoreDomain();
        String username = user.getWrapped().getUserName();

        try {
            UserRealm userRealm = Utils.getUserRealm(user.getWrapped().getTenantDomain());
            if (userRealm != null) {
                UserStoreManager userStore = Utils.getUserStoreManager(tenantDomain, userRealm, userStoreDomain);
                if (userStore != null) {
                    String userId = UserSessionStore.getInstance().getUserId(username, Utils.getTenantId(tenantDomain), userStoreDomain);
                    result = UserFunctionsServiceHolder.getInstance().getUserSessionManagementService().terminateSessionsByUserId(userId);
                }
            }
            if (result && LOG.isDebugEnabled()) {
                LOG.debug("All active sessions killed for user: " + username);
            }
        } catch (SessionManagementException e) {
            LOG.error("Error occurred while killing sessions: ", e);
        } catch (FrameworkException e) {
            LOG.error("Error in evaluating the function ", e);
        } catch (UserSessionException e) {
            LOG.error("Error occurred while retrieving the UserID: ", e);
        } finally {
            return result;
        }
    }
}
