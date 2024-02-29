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
import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

/**
 * Function to check whether the specified user belongs to one of the groups specified in the list of user groups.
 */
public class IsMemberOfAnyOfGroupsFunctionImpl implements IsMemberOfAnyOfGroupsFunction {

    private static final Log LOG = LogFactory.getLog(IsMemberOfAnyOfGroupsFunctionImpl.class);

    private static final String DEFAULT_OIDC_GROUPS_CLAIM_URI = "groups";
    private static final String OPENIDCONNECT_AUTHENTICATOR_NAME = "OpenIDConnectAuthenticator";
    private static final String GROUPS_LOCAL_CLAIM = "http://wso2.org/claims/groups";

    @Override
    @HostAccess.Export
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
     * Checks if the federated user belongs to any of the specified user groups.
     *
     * @param user The authenticated user.
     * @param groupNames A list of group names.
     * @return true if the federated user is a member of any of the specified groups, false otherwise.
     */
    private boolean isFederatedUserMemberOfAnyGroup(JsAuthenticatedUser user, List<String> groupNames) {

        // Get the claim URI for groups claim from the claim mappings for federated idp.
        String groupsClaimURI = getGroupsClaimURI(user);
        if (StringUtils.isEmpty(groupsClaimURI)) {
            return false;
        }
        Set<String> groupsOfFederatedUser = getGroupsOfFederatedUser(user, groupsClaimURI);
        if (groupsOfFederatedUser.isEmpty()) {
            return false;
        }
        return groupNames.stream().anyMatch(groupsOfFederatedUser::contains);
    }

    private String getGroupsClaimURI(JsAuthenticatedUser user) {

        String groupsClaimURI = getGroupsClaimURIByClaimMappings(user);
        if (groupsClaimURI == null && user.getContext().getCurrentAuthenticator() != null &&
                OPENIDCONNECT_AUTHENTICATOR_NAME.equals(user.getContext().getCurrentAuthenticator())) {
            groupsClaimURI = DEFAULT_OIDC_GROUPS_CLAIM_URI;
        }
        return groupsClaimURI;
    }

    /**
     * Get the groups of the federated user.
     *
     * @param user Authenticate user.
     * @param groupsClaimURI URI of the groups claim.
     * @return groups of the federated user .
     */
    private Set<String> getGroupsOfFederatedUser(JsAuthenticatedUser user, String groupsClaimURI) {

        String groups = null;
        Set<String> groupsOfFederatedUser = new HashSet<>();
        if (StringUtils.isNotEmpty(groupsClaimURI) && MapUtils.isNotEmpty(user.getWrapped().getUserAttributes())) {
            groups = user.getWrapped().getUserAttributes().entrySet().stream().filter(
                    userAttribute -> groupsClaimURI.equals(userAttribute.getKey().getRemoteClaim().getClaimUri()))
                        .map(Map.Entry::getValue)
                        .findFirst()
                        .orElse(null);
        }
        if (groups != null) {
            String[] groupArray = groups.split(FrameworkUtils.getMultiAttributeSeparator());
            groupsOfFederatedUser.addAll(Arrays.asList(groupArray));
        }
        return groupsOfFederatedUser;
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

    /**
     * Retrieve the groups claim configured for the federated IDP.
     *
     * @param user Authenticated user.
     * @return  groups claim configured for the IDP.
     */
    private static String getGroupsClaimURIByClaimMappings(JsAuthenticatedUser user){

        ClaimMapping[] claimMappings = getClaimMappings(user);
        if (claimMappings == null || claimMappings.length == 0) {
            return null;
        }

        // Here we get the mapping for the local groups claim URI.
        ClaimMapping groupsClaimMapping = Arrays.stream(claimMappings).filter(claimMapping ->
                        StringUtils.equals(GROUPS_LOCAL_CLAIM, claimMapping.getLocalClaim().getClaimUri()))
                .findFirst()
                .orElse(null);

        return groupsClaimMapping != null ? groupsClaimMapping.getRemoteClaim().getClaimUri() : null;

    }

    /**
     * Retrieve the claim mappings for the federated IDP.
     *
     * @param user Authenticated user.
     * @return  groups claim configured for the IDP.
     * @throws IdentityProviderManagementException
     */
    private static ClaimMapping[] getClaimMappings(JsAuthenticatedUser user) {

        ExternalIdPConfig idp = user.getContext().getExternalIdP();
        return (idp != null) ? idp.getClaimMappings() : null;
    }
}
