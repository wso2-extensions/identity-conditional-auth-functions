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

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.conditional.auth.functions.user.internal.UserFunctionsServiceHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Arrays;

/**
 * Utility methods required for user functions.
 */
public class Utils {

    private static final String USERNAME_LOCAL_CLAIM = "http://wso2.org/claims/username";

    /**
     * Get userRealm for the given tenantDomain.
     *
     * @param tenantDomain Tenant domain relevant to the required userRealm
     * @return UserRealm as an object
     * @throws FrameworkException Error occurred during userRealm retrieving
     */
    public static UserRealm getUserRealm(String tenantDomain) throws FrameworkException {

        UserRealm realm;
        RealmService realmService = UserFunctionsServiceHolder.getInstance().getRealmService();
        try {
            int tenantId = getTenantId(tenantDomain);
            realm = (UserRealm) realmService.getTenantUserRealm(tenantId);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new FrameworkException(
                    "Error occurred while retrieving the Realm for " + tenantDomain + " to retrieve user roles", e);
        }
        return realm;
    }

    /**
     * Get userStore manager for the given parameters.
     *
     * @param tenantDomain Tenant domain relevant to the required userStore manager
     * @param realm        User realm name relevant to the userStore manager
     * @param userDomain   User domain name relevant to the userStore manager
     * @return UserStore manager object
     * @throws FrameworkException Error occurred while retrieving userStore manager or undefined userStore domain and
     *                            tenantDomain
     */
    public static UserStoreManager getUserStoreManager(String tenantDomain, UserRealm realm, String userDomain)
            throws FrameworkException {

        UserStoreManager userStore = null;
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

    /**
     * Get tenantId for the given tenantDomain.
     *
     * @param tenantDomain Tenant domain relevant to the required tenantId
     * @return tenantId as an Integer
     */
    public static int getTenantId(String tenantDomain) {

        return (tenantDomain == null) ? org.wso2.carbon.utils.multitenancy.MultitenantConstants
                .INVALID_TENANT_ID : IdentityTenantUtil.getTenantId(tenantDomain);
    }

    /**
     * Retrieve the user id claim configured for the federated IDP.
     *
     * @param federatedIdpName  Federated IDP name.
     * @param tenantDomain      Tenant domain.
     * @return  User ID claim configured for the IDP.
     * @throws IdentityProviderManagementException
     */
    public static String getUserIdClaimURI(String federatedIdpName, String tenantDomain)
            throws IdentityProviderManagementException {

        String userIdClaimURI = null;
        IdentityProvider idp =
                UserFunctionsServiceHolder.getInstance().getIdentityProviderManagementService()
                        .getIdPByName(federatedIdpName, tenantDomain);
        if (idp == null) {
            return null;
        }
        ClaimConfig claimConfigs = idp.getClaimConfig();
        if (claimConfigs == null) {
            return null;
        }
        ClaimMapping[] claimMappings = claimConfigs.getClaimMappings();
        if (claimMappings == null || claimMappings.length < 1) {
            return null;
        }
        userIdClaimURI = claimConfigs.getUserClaimURI();
        if (userIdClaimURI != null) {
            return userIdClaimURI;
        }
        ClaimMapping userNameClaimMapping = Arrays.stream(claimMappings).filter(claimMapping ->
                StringUtils.equals(USERNAME_LOCAL_CLAIM, claimMapping.getLocalClaim().getClaimUri()))
                .findFirst()
                .orElse(null);
        if (userNameClaimMapping != null) {
            userIdClaimURI = userNameClaimMapping.getRemoteClaim().getClaimUri();
        }
        return userIdClaimURI;
    }

}
