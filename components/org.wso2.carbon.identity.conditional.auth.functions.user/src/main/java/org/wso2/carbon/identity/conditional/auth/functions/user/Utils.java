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
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.core.util.AnonymousSessionUtil;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.conditional.auth.functions.user.internal.UserFunctionsServiceHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Utility methods required for user functions.
 */
public class Utils {

    private static final String USERNAME_LOCAL_CLAIM = "http://wso2.org/claims/username";
    private static final String SUB_ATTRIBUTE = "sub";
    private static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";

    /**
     * Get userRealm for the given tenantDomain.
     *
     * @param tenantDomain Tenant domain relevant to the required userRealm
     * @return UserRealm as an object
     * @throws FrameworkException Error occurred during userRealm retrieving
     */
    public static UserRealm getUserRealm(String tenantDomain) throws FrameworkException {

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
        ClaimMapping[] claimMappings = getIdPClaimMapping(federatedIdpName, tenantDomain);
        if (claimMappings == null || claimMappings.length < 1) {
            return null;
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

    /**
     * Resolve the userID claim URI from the IdP mapping or the default OIDC mapping.
     *
     * @param federatedIdpName federated IdP name.
     * @param tenantDomain  tenant domain.
     * @return userIDcClaimURI.
     * @throws IdentityProviderManagementException If an error occurred in resolving userID claim URI.
     */
    public static String resolveUserIDClaimURIFromMapping(String federatedIdpName, String tenantDomain)
            throws IdentityProviderManagementException {

        List<ExternalClaim> defaultClaims = getDefaultOIDCDialectClaims(tenantDomain);
        ClaimMapping[] idpClaimMappings = getIdPClaimMapping(federatedIdpName, tenantDomain);
        String userIDLocalClaimURI = getMappedLocalClaimURI(defaultClaims, SUB_ATTRIBUTE);
        if (userIDLocalClaimURI == null) {
            return null;
        }
        if (idpClaimMappings != null) {
            ClaimMapping userNameClaimMapping = Arrays.stream(idpClaimMappings).filter(claimMapping ->
                            StringUtils.equals(userIDLocalClaimURI, claimMapping.getLocalClaim().getClaimUri()))
                    .findFirst()
                    .orElse(null);
            if (userNameClaimMapping != null) {
                return userNameClaimMapping.getRemoteClaim().getClaimUri();
            }
        }
        if (defaultClaims != null && !defaultClaims.isEmpty()) {
            ExternalClaim claim = defaultClaims.stream().filter(externalClaim -> userIDLocalClaimURI
                            .equalsIgnoreCase(externalClaim.getMappedLocalClaim()))
                    .findFirst()
                    .orElse(null);
            if (claim != null) {
                return claim.getClaimURI();
            }
        }
        return null;
    }


    /**
     * Get claim mapping for Identity provider.
     *
     * @param federatedIdpName Name of the Identity provider.
     * @param tenantDomain Tenant domain.
     * @return claimMappings
     * @throws IdentityProviderManagementException If an error occurred in getting claim mapping.
     */
    private static ClaimMapping[] getIdPClaimMapping(String federatedIdpName, String tenantDomain)
            throws IdentityProviderManagementException {

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
        return claimMappings;
    }

    /**
     * Get default claim mapping.
     *
     * @param tenantDomain tenant domain.
     * @return default claim mapping.
     * @throws IdentityProviderManagementException If an error occurred in getting default claim mapping.
     */
    private static List<ExternalClaim> getDefaultOIDCDialectClaims(String tenantDomain)
            throws IdentityProviderManagementException {

        try {
            return UserFunctionsServiceHolder.getInstance()
                    .getClaimMetadataManagementService()
                    .getExternalClaims(OIDC_DIALECT, tenantDomain);

        } catch (ClaimMetadataException e) {
            throw new IdentityProviderManagementException("Error while fetching default oidc dialect claim mapping " +
                    "for tenantDomain: " + tenantDomain);
        }
    }

    /**
     * Get the local mapped claim URI for an identity provider claim.
     *
     * @param claims Identity provider claim mapping.
     * @param idpClaim  Identity provider claim.
     * @return  Local claim URI.
     */
    private static String getMappedLocalClaimURI(List<ExternalClaim> claims, String idpClaim) {

        ExternalClaim claim = claims.stream().filter(externalClaim -> idpClaim.equalsIgnoreCase(externalClaim
                        .getClaimURI()))
                .findFirst()
                .orElse(null);
        if (claim != null) {
            return claim.getMappedLocalClaim();
        }
        return null;
    }
}
