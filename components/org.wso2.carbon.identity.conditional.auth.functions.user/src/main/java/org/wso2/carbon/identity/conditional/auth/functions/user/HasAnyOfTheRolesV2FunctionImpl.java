/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.AssociatedRolesConfig;
import org.wso2.carbon.identity.application.common.model.RoleV2;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.conditional.auth.functions.user.internal.UserFunctionsServiceHolder;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.model.RoleBasicInfo;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Implementation of the function to check if the given user has at least one of the given roles(v2).
 */
public class HasAnyOfTheRolesV2FunctionImpl implements HasAnyOfTheRolesV2Function {

    private static final Log LOG = LogFactory.getLog(HasAnyOfTheRolesV2FunctionImpl.class);

    @Override
    public boolean hasAnyOfTheRolesV2(JsAuthenticationContext context, List<String> roleNames) {

        if (roleNames == null || roleNames.isEmpty()) {
            return false;
        }

        AuthenticatedUser subject = context.getWrapped().getSubject();
        if (subject.isFederatedUser()) {
            return false;
        }

        String applicationName = context.getWrapped().getServiceProviderName();
        String tenantDomain = context.getWrapped().getTenantDomain();

        ServiceProvider application;
        try {
            application = UserFunctionsServiceHolder.getInstance().getApplicationManagementService()
                    .getApplicationExcludingFileBasedSPs(applicationName, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            LOG.error("Error occurred while retrieving the application", e);
            return false;
        }

        AssociatedRolesConfig associatedRolesConfig = application.getAssociatedRolesConfig();
        if (associatedRolesConfig == null || associatedRolesConfig.getRoles() == null
                || associatedRolesConfig.getRoles().length == 0) {
            // No roles associated with the application.
            return false;
        }

        List<RoleBasicInfo> roleListOfUser;
        try {
            roleListOfUser = UserFunctionsServiceHolder.getInstance().getRoleManagementService()
                    .getRoleListOfUser(subject.getUserId(), tenantDomain);
        } catch (IdentityRoleManagementException | UserIdNotFoundException e) {
            LOG.error("Error occurred while retrieving the user", e);
            return false;
        }

        if (roleListOfUser == null || roleListOfUser.isEmpty()) {
            return false;
        }

        List<RoleV2> associatedRoles = Arrays.asList(associatedRolesConfig.getRoles());
        for (String roleName : roleNames) {
            // Check if the provided role name is associated with the application.
            Optional<RoleV2> roleOptional =
                    associatedRoles.stream().filter(role -> role.getName().equals(roleName)).findFirst();

            if (roleOptional.isPresent()) {
                // Check if the user has the role from role id.
                Optional<RoleBasicInfo> role2 = roleListOfUser.stream()
                        .filter(roleBasicInfo -> roleBasicInfo.getId().equals(roleOptional.get().getId()))
                        .findFirst();
                if (role2.isPresent()) {
                    return true;
                }
            }
        }

        return false;
    }
}
