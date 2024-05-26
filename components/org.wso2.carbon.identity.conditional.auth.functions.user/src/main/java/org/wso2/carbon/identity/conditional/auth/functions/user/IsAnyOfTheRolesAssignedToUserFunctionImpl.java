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
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;

import java.util.Arrays;
import java.util.List;

/**
 * Function to check whether the specified user belongs to any of the specified roles.
 * Roles are directly retrieved from database without checking in the cache first.
 */
public class IsAnyOfTheRolesAssignedToUserFunctionImpl implements IsAnyOfTheRolesAssignedToUserFunction {

    private static final Log LOG = LogFactory.getLog(IsAnyOfTheRolesAssignedToUserFunctionImpl.class);
    private final static String DEFAULT_FILTER = "*";

    @Override
    @HostAccess.Export
    public boolean IsAnyOfTheRolesAssignedToUser(JsAuthenticatedUser user, List<String> roleNames) {

        boolean result = false;
        String username = user.getWrapped().getUserName();

        try {
            UserStoreManager userStore = getUserStore(user.getWrapped());
            if (userStore instanceof AbstractUserStoreManager) {
                String[] roleListOfUser = ((AbstractUserStoreManager) userStore)
                        .getRoleListOfUserFromDatabase(username, DEFAULT_FILTER);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Retrieved roles: " + roleListOfUser + " of user: " + username);
                }
                result = Arrays.stream(roleListOfUser).anyMatch(roleNames::contains);
            }
        } catch (UserStoreException e) {
            LOG.error("Error occurred while retrieving the roles from user store for the user:  " + username, e);
        }

        return result;
    }

    private UserStoreManager getUserStore(AuthenticatedUser user) {

        String tenantDomain = user.getTenantDomain();
        String userStoreDomain = user.getUserStoreDomain();
        try {
            UserRealm userRealm = Utils.getUserRealm(user.getTenantDomain());
            if (userRealm != null) {
                return Utils.getUserStoreManager(tenantDomain, userRealm, userStoreDomain);
            }
        } catch (FrameworkException e) {
            LOG.error("Error occurred while getting the user store.", e);
        }
        return null;
    }
}
