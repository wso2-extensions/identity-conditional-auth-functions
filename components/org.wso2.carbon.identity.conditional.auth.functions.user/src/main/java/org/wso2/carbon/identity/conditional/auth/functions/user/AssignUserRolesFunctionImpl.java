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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.util.List;

/**
 * Function to update given roles for a given user.
 * The purpose is to perform role assigning during dynamic authentication.
 */
public class AssignUserRolesFunctionImpl implements AssignUserRolesFunction {

    private static final Log LOG = LogFactory.getLog(AssignUserRolesFunctionImpl.class);

    /**
     * {@inheritDoc}
     *
     * @param user           Authenticated user.
     * @param assigningRoles Roles to be assigned.
     * @return <code>true</code> If the role assigning is successfully completed. <code>false</code> for any other case.
     */
    @Override
    @HostAccess.Export
    public boolean assignUserRoles(JsAuthenticatedUser user, List<String> assigningRoles) {

        if (user == null) {
            LOG.error("User is not defined");
            return false;
        }
        if (assigningRoles == null) {
            LOG.error("Assigning roles are not defined");
            return false;
        }
        try {
            if (user.getWrapped() != null) {
                String tenantDomain = user.getWrapped().getTenantDomain();
                String userStoreDomain = user.getWrapped().getUserStoreDomain();
                String username = user.getWrapped().getUserName();
                UserRealm userRealm = Utils.getUserRealm(tenantDomain);
                if (userRealm != null) {
                    UserStoreManager userStore = Utils.getUserStoreManager(tenantDomain, userRealm, userStoreDomain);
                    userStore.updateRoleListOfUser(
                            username,
                            new String[0],
                            assigningRoles.toArray(new String[0])
                    );
                    return true;
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Unable to find userRealm for the user: "
                                + username + " in userStoreDomain: " + userStoreDomain);
                    }
                }
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Unable to get wrapped content for the user");
                }
            }
        } catch (UserStoreException e) {
            LOG.error("Error while getting user from the store", e);
        } catch (FrameworkException e) {
            LOG.error("Error while retrieving userRealm and userStoreManager", e);
        }
        return false;
    }
}
