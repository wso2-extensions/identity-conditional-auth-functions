/*
 * Copyright (c) 2019-2025, WSO2 LLC. (http://www.wso2.com).
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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.exception.session.mgt.SessionManagementException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.UserSession;
import org.wso2.carbon.identity.conditional.auth.functions.user.exception.UserSessionRetrievalException;
import org.wso2.carbon.identity.conditional.auth.functions.user.internal.UserFunctionsServiceHolder;
import org.wso2.carbon.identity.conditional.auth.functions.user.model.JsUserSession;
import org.wso2.carbon.identity.conditional.auth.functions.user.model.JsWrapperFactoryProvider;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.core.UserRealm;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Function to retrieve the active sessions of the specified user.
 */
public class GetUserSessionsFunctionImpl implements GetUserSessionsFunction {

    private static final Log LOG = LogFactory.getLog(GetUserSessionsFunctionImpl.class);

    @Override
    @HostAccess.Export
    public List<JsUserSession> getUserSessions(JsAuthenticatedUser user) {

        List<JsUserSession> sessionsForUser = null;
        try {
            sessionsForUser = getUserSessions(user.getWrapped())
                    .stream().map(JsWrapperFactoryProvider.getInstance().getWrapperFactory()::createJsUserSession)
                    .collect(Collectors.toList());
        } catch (UserSessionRetrievalException e) {
            LOG.error(e);
        }
        return sessionsForUser;
    }

    private List<UserSession> getUserSessions(AuthenticatedUser authenticatedUser)
            throws UserSessionRetrievalException {

        List<UserSession> userSessions = null;
        String tenantDomain = getUserTenantDomain(authenticatedUser);

        try {
            UserRealm userRealm = Utils.getUserRealm(tenantDomain);
            if (userRealm != null) {
                String userId = authenticatedUser.getUserId();
                userSessions = UserFunctionsServiceHolder.getInstance()
                        .getUserSessionManagementService().getSessionsByUserId(userId, tenantDomain);
            }
        } catch (SessionManagementException e) {
            throw new UserSessionRetrievalException("Error occurred while retrieving sessions: ", e);
        } catch (FrameworkException e) {
            throw new UserSessionRetrievalException("Error in evaluating the function ", e);
        } catch (UserIdNotFoundException e) {
            throw new UserSessionRetrievalException("Error occurred while retrieving the UserID: ", e);
        }
        return userSessions;
    }

    private String getUserTenantDomain(AuthenticatedUser authenticatedUser) throws UserSessionRetrievalException {

        String tenantDomain = authenticatedUser.getTenantDomain();
        String userAccessingOrganization = authenticatedUser.getAccessingOrganization();
        if (StringUtils.isNotBlank(userAccessingOrganization)) {
            try {
                tenantDomain = UserFunctionsServiceHolder.getInstance().getOrganizationManager()
                        .resolveTenantDomain(userAccessingOrganization);
            } catch (OrganizationManagementException e) {
                throw new UserSessionRetrievalException(
                        "Error occurred while resolving tenant domain of user accessing organization: " +
                                userAccessingOrganization, e);
            }
        }
        return tenantDomain;
    }
}
