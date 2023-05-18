/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Function to check whether the specified user belongs to one of the groups specified in the list of user groups.
 */
public class IsMemberOfAnyOfGroupsFunctionImpl implements IsMemberOfAnyOfGroupsFunction {

    private static final Log LOG = LogFactory.getLog(IsMemberOfAnyOfGroupsFunctionImpl.class);

    private static final String GROUPS_LOCAL_CLAIM_URI = "groups";

    @Override
    public boolean isMemberOfAnyOfGroups(JsAuthenticatedUser user, List<String> groupNames) {

        boolean result = false;
        String tenantDomain = user.getWrapped().getTenantDomain();
        String userStoreDomain = user.getWrapped().getUserStoreDomain();
        String username = user.getWrapped().getUserName();

        if (user.getWrapped().isFederatedUser()) {
            return isFederatedUserMemberOfAnyGroup(user, groupNames);
        }

        // Build the user store domain aware role name list.
        List<String> groupsWithDomain = getDomainAwareGroupNames(userStoreDomain, groupNames);
        try {
            UserRealm userRealm = Utils.getUserRealm(user.getWrapped().getTenantDomain());
            if (userRealm != null) {
                UserStoreManager userStore = Utils.getUserStoreManager(tenantDomain, userRealm, userStoreDomain);
                if (userStore != null) {
                    // List returned by the user store will contain the roles and groups.
                    String[] roleListOfUser = userStore.getRoleListOfUser(username);
                    result = Arrays.stream(roleListOfUser).anyMatch(groupsWithDomain::contains);
                }
            }
        } catch (FrameworkException e) {
            LOG.error("Error in evaluating the function ", e);
        } catch (UserStoreException e) {
            LOG.error("Error in getting user from store at the function ", e);
        }
        return result;
    }

    /**
     * Check the federated user belongs to one of the groups specified in the list of user groups.
     *
     * @param user Authenticate user.
     * @param groupNames      List of groups.
     * @return whether the federated user belongs to one of the groups specified in the list of user groups .
     */
    private boolean isFederatedUserMemberOfAnyGroup(JsAuthenticatedUser user, List<String> groupNames) {

        String[] groupsOfFederatedUser = null;
        String groupsClaimValue = null;
        String federatedIdPName = user.getWrapped().getFederatedIdPName();
        String tenantDomain = user.getWrapped().getTenantDomain();
        try {
            // Get the claim URI for groups claim from the claim mappings for federated idp.
            String groupsClaimURI = Utils.getGroupsClaimURIByClaimMappings(federatedIdPName, tenantDomain);
            if (groupsClaimURI == null) {
                groupsClaimURI = GROUPS_LOCAL_CLAIM_URI;
            }
            groupsClaimValue = getGroupsClaimValue(user, groupsClaimURI);
            if (groupsClaimValue == null) {
                return false;
            }
            groupsOfFederatedUser = groupsClaimValue.split(FrameworkUtils.getMultiAttributeSeparator());
        } catch (IdentityProviderManagementException e) {
            String msg = "Error while retrieving identity provider by name: " + federatedIdPName;
            LOG.error(msg, e);
        }
        return Arrays.stream(groupsOfFederatedUser).anyMatch(groupNames::contains);
    }

    /**
     * Get the value of the given groups claimURI.
     *
     * @param user Authenticate user.
     * @param groupsClaimURI URI of the groups claim.
     * @return groups claim value .
     */
    private String getGroupsClaimValue(JsAuthenticatedUser user, String groupsClaimURI) {

        String groups = null;
        if (StringUtils.isNotEmpty(groupsClaimURI) && MapUtils.isNotEmpty(user.getWrapped().getUserAttributes())) {
            groups = user.getWrapped().getUserAttributes().entrySet().stream().filter(
                    userAttribute -> userAttribute.getKey().getRemoteClaim().getClaimUri().equals(groupsClaimURI))
                        .map(Map.Entry::getValue)
                        .findFirst()
                        .orElse(null);
        }
        return groups;
    }

    /**
     * Build user store aware group names list.
     *
     * @param userStoreDomain User store domain name.
     * @param groupNames      List of groups.
     * @return List of groups with the user store domain name prepended to the front.
     */
    private List<String> getDomainAwareGroupNames(String userStoreDomain, List<String> groupNames) {

        /*
        For primary user store, the user store domain name is not prepended to the group names. Therefore, for
        primary user store group check we do not need to prepend the user store domain name,
         */
        if (UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME.equals(userStoreDomain)) {
            return groupNames;
        }
        List<String> groupsWithDomain = new ArrayList<>();
        for (String groupName : groupNames) {
            if (groupName.contains(UserCoreConstants.DOMAIN_SEPARATOR)) {
                // Having '/' in the group name implies, having the user store domain name in the group name.
                groupsWithDomain.add(groupName);
            } else {
                groupsWithDomain.add(userStoreDomain + UserCoreConstants.DOMAIN_SEPARATOR + groupName);
            }
        }
        return groupsWithDomain;
    }
}
