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
import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.AssociatedRolesConfig;
import org.wso2.carbon.identity.application.common.model.RoleV2;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.conditional.auth.functions.user.internal.UserFunctionsServiceHolder;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Implementation of the function to assign given roles for a given user.
 */
public class AssignUserRolesV2FunctionImpl implements AssignUserRolesV2Function {

    private static final Log LOG = LogFactory.getLog(AssignUserRolesV2FunctionImpl.class);

    @Override
    @HostAccess.Export
    public boolean assignUserRolesV2(JsAuthenticationContext context, List<String> roleListToAssign) {

        if (roleListToAssign == null || roleListToAssign.isEmpty()) {
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

        List<RoleV2> associatedRoles = Arrays.asList(associatedRolesConfig.getRoles());
        List<RoleV2> allowedRoleListToAssign = new ArrayList<>();

        for (String roleName : roleListToAssign) {
            String processedRoleName =
                    UserCoreConstants.INTERNAL_DOMAIN.equalsIgnoreCase(UserCoreUtil.extractDomainFromName(roleName))
                            ? UserCoreUtil.removeDomainFromName(roleName)
                            : roleName;

            // Check if the processed role name is associated with the application.
            Optional<RoleV2> roleOptional =
                    associatedRoles.stream().filter(role -> role.getName().equals(processedRoleName)).findFirst();
            roleOptional.ifPresent(allowedRoleListToAssign::add);
        }

        if (allowedRoleListToAssign.isEmpty()) {
            return false;
        }

        for (RoleV2 role : allowedRoleListToAssign) {
            try {
                UserFunctionsServiceHolder.getInstance().getRoleManagementService()
                        .updateUserListOfRole(role.getId(), Collections.singletonList(subject.getUserId()),
                                Collections.emptyList(), tenantDomain);
            } catch (IdentityRoleManagementException | UserIdNotFoundException e) {
                LOG.error("Error occurred while updating the roles of the user", e);
                return false;
            }
        }

        return true;
    }
}
