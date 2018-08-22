/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.user;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.core.util.AnonymousSessionUtil;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.conditional.auth.functions.user.internal.UserFunctionsServiceHolder;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.util.List;

/**
 * Function to remove given roles from the a given user.
 * The purpose is to perform role removing during dynamic authentication.
 */
public class RemoveUserRolesFunctionImpl implements RemoveUserRolesFunction {

    private static final Log LOG = LogFactory.getLog(RemoveUserRolesFunctionImpl.class);

    /**
     * {@inheritDoc}
     *
     * @param user          Authenticated user.
     * @param removingRoles Roles to be removed.
     * @return <code>true</code> If the role assigning is successfully completed. <code>false</code> for any other case.
     */
    @Override
    public boolean removeUserRoles(JsAuthenticatedUser user, List<String> removingRoles) {

        if (user != null && removingRoles != null) {
            try {
                if (user.getWrapped() != null) {
                    String tenantDomain = user.getWrapped().getTenantDomain();
                    String userStoreDomain = user.getWrapped().getUserStoreDomain();
                    String username = user.getWrapped().getUserName();
                    UserRealm userRealm = getUserRealm(tenantDomain);
                    if (userRealm != null) {
                        UserStoreManager userStore = getUserStoreManager(tenantDomain, userRealm, userStoreDomain);
                        if (userStore != null) {
                            userStore.updateRoleListOfUser(
                                    username,
                                    removingRoles.toArray(new String[0]),
                                    new String[0]
                            );
                            return true;
                        } else {
                            LOG.debug("Unable to find userStore for username "
                                    + username + " in userStoreDomain " + userStoreDomain);
                        }
                    } else {
                        LOG.debug("Unable to find userRealm for the user "
                                + username + " in userStoreDomain " + userStoreDomain);
                    }
                } else {
                    LOG.debug("Unable to get wrapped content for the user");
                }
            } catch (UserStoreException e) {
                LOG.error("Error while getting user from the store", e);
            } catch (FrameworkException e) {
                LOG.error("Error while evaluating the function ", e);
            }
        } else {
            if (user == null) {
                LOG.error("Invalid value for the user");
            } else {
                LOG.error("Invalid value for the new roles");
            }
        }
        return false;
    }

    private UserRealm getUserRealm(String tenantDomain) throws FrameworkException {

        UserRealm realm;
        try {
            realm = AnonymousSessionUtil.getRealmByTenantDomain(UserFunctionsServiceHolder.getInstance()
                    .getRegistryService(), UserFunctionsServiceHolder.getInstance().getRealmService(), tenantDomain);
        } catch (CarbonException e) {
            throw new FrameworkException(
                    "Error occurred while retrieving the Realm for " + tenantDomain + " to retrieve user roles", e);
        }
        return realm;
    }

    private UserStoreManager getUserStoreManager(String tenantDomain, UserRealm realm, String userDomain)
            throws FrameworkException {

        UserStoreManager userStore;
        try {
            if (StringUtils.isNotBlank(userDomain)) {
                userStore = realm.getUserStoreManager().getSecondaryUserStoreManager(userDomain);
            } else {
                userStore = realm.getUserStoreManager();
            }

            if (userStore == null) {
                throw new FrameworkException(
                        String.format("Invalid user store domain (given : %s) or tenant domain (given: %s).",
                                userDomain, tenantDomain));
            }
        } catch (UserStoreException e) {
            throw new FrameworkException(
                    "Error occurred while retrieving the UserStoreManager from Realm for " + tenantDomain
                            + " to retrieve user roles", e);
        }
        return userStore;
    }
}
