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
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.model.RoleBasicInfo;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.Group;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.wso2.carbon.user.core.UserCoreConstants.APPLICATION_DOMAIN;
import static org.wso2.carbon.user.core.UserCoreConstants.INTERNAL_DOMAIN;

/**
 * Implementation of the function to check if the given user has at least one of the given roles(v2).
 */
public class HasAnyOfTheRolesV2FunctionImpl implements HasAnyOfTheRolesV2Function {

    private static final Log LOG = LogFactory.getLog(HasAnyOfTheRolesV2FunctionImpl.class);

    @Override
    @HostAccess.Export
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
            String processedRoleName =
                    UserCoreConstants.INTERNAL_DOMAIN.equalsIgnoreCase(UserCoreUtil.extractDomainFromName(roleName))
                            ? UserCoreUtil.removeDomainFromName(roleName)
                            : roleName;

            // Check if the processed role name is associated with the application.
            Optional<RoleV2> roleOptional =
                    associatedRoles.stream().filter(role -> role.getName().equals(processedRoleName)).findFirst();

            if (roleOptional.isPresent()) {
                // Check if the user has the role from role id.
                Optional<RoleBasicInfo> role = roleListOfUser.stream()
                        .filter(roleBasicInfo -> roleBasicInfo.getId().equals(roleOptional.get().getId()))
                        .findFirst();
                if (role.isPresent()) {
                    return true;
                }
            }
        }

        try {
            List<String> roleIdsFromUserGroups = getRoleIdsFromUserGroups(subject.getUserId(),
                    IdentityTenantUtil.getTenantId(tenantDomain), tenantDomain);
            for (String roleName : roleNames) {
                String processedRoleName =
                        UserCoreConstants.INTERNAL_DOMAIN.equalsIgnoreCase(UserCoreUtil.extractDomainFromName(roleName))
                                ? UserCoreUtil.removeDomainFromName(roleName)
                                : roleName;

                // Check if the processed role name is associated with the application.
                Optional<RoleV2> roleOptional =
                        associatedRoles.stream().filter(role -> role.getName().equals(processedRoleName)).findFirst();

                if (roleOptional.isPresent()) {
                    // Check if the user has the role from role id.
                    Optional<String> role = roleIdsFromUserGroups.stream()
                            .filter(roleId -> roleId.equals(roleOptional.get().getId()))
                            .findFirst();
                    if (role.isPresent()) {
                        return true;
                    }
                }
            }
        } catch (UserStoreException | IdentityRoleManagementException | UserIdNotFoundException e) {
            LOG.error("Error occurred while retrieving roles of user's groups", e);
            return false;
        }

        return false;
    }

    /**
     * Get the role ids of the roles associated to user's groups.
     *
     * @param userId       User id.
     * @param tenantId     Tenant Id.
     * @param tenantDomain Tenant domain.
     * @return - Roles ids.
     */
    private static List<String> getRoleIdsFromUserGroups(String userId, int tenantId, String tenantDomain)
            throws UserStoreException, IdentityRoleManagementException {

        List<String> userGroups = new ArrayList<>();
        RealmService realmService = UserCoreUtil.getRealmService();
        UserStoreManager userStoreManager = realmService.getTenantUserRealm(tenantId).getUserStoreManager();
        List<Group> groups = ((AbstractUserStoreManager) userStoreManager).getGroupListOfUser(userId, null, null);
        for (Group group : groups) {
            String groupDomainName = UserCoreUtil.extractDomainFromName(group.getGroupName());
            if (!INTERNAL_DOMAIN.equalsIgnoreCase(groupDomainName) &&
                    !APPLICATION_DOMAIN.equalsIgnoreCase(groupDomainName)) {
                userGroups.add(group.getGroupID());
            }
        }
        if (userGroups.isEmpty()) {
            return Collections.emptyList();
        }

        return UserFunctionsServiceHolder.getInstance().getRoleManagementService()
                .getRoleIdListOfGroups(userGroups, tenantDomain);
    }

}
