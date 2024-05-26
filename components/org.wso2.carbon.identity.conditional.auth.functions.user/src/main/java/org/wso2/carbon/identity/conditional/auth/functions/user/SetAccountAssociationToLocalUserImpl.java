/*
 *  Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileException;
import org.wso2.carbon.identity.user.profile.mgt.dao.UserProfileMgtDAO;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;

import java.util.Map;

public class SetAccountAssociationToLocalUserImpl implements SetAccountAssociationToLocalUser {

    private static final Log log = LogFactory.getLog(SetAccountAssociationToLocalUserImpl.class);

    @Override
    @HostAccess.Export
    public boolean doAssociationWithLocalUser(JsAuthenticatedUser federatedUser, String username, String tenantDomain,
                                              String userStoreDomainName) {

        String federatedIdpName = null;
        boolean successfulAssociation = false;
        try {
            if (federatedUser != null) {
                if (federatedUser.getWrapped().isFederatedUser()) {
                    if (!StringUtils.equalsIgnoreCase(tenantDomain, federatedUser.getWrapped().getTenantDomain())) {
                        log.error("Association failed due to mismatch in tenant. The tenant sent for association: "
                                + tenantDomain + " does not match the tenant of the federated user: " + federatedUser
                                .getWrapped().getTenantDomain());
                        return false;
                    }
                    federatedIdpName = federatedUser.getWrapped().getFederatedIdPName();
                    String userIdClaimURI = Utils.getUserIdClaimURI(federatedIdpName, tenantDomain);
                    String externalSubject;
                    if (StringUtils.isNotEmpty(userIdClaimURI)) {
                        externalSubject = federatedUser.getWrapped().getUserAttributes().entrySet().stream().filter(
                                userAttribute -> userAttribute.getKey().getRemoteClaim().getClaimUri()
                                        .equals(userIdClaimURI))
                                .map(Map.Entry::getValue)
                                .findFirst()
                                .orElse(null);
                    } else {
                        externalSubject = federatedUser.getWrapped().getAuthenticatedSubjectIdentifier();
                    }
                    String externalIdpName = federatedUser.getWrapped().getFederatedIdPName();
                    if (externalSubject != null && externalIdpName != null) {
                        successfulAssociation = associateID(externalIdpName, externalSubject, username, tenantDomain,
                                userStoreDomainName);
                    } else {
                        log.warn(" Authenticated user or External IDP may be null Authenticated User: " +
                                externalSubject + " and the External IDP name: " + externalIdpName);
                    }
                } else {
                    log.warn("User " + federatedUser.getWrapped().getAuthenticatedSubjectIdentifier() + " " +
                            "is not a federated user.");
                }
            } else {
                log.warn(" Federated user is null ");
            }
        } catch (IdentityProviderManagementException e) {
            String msg =
                    "Error while retrieving identity provider by name: " + federatedIdpName;
            log.error(msg, e);
        }
        return successfulAssociation;
    }

    /**
     * Create association to the local user with a federated user.
     *
     * @param idpID               External IDP name.
     * @param associatedID        External authenticated user.
     * @param username            Local username.
     * @param tenantDomain        Tenant domain.
     * @param userStoreDomainName Userstore domain name.
     * @return The status of the association creation.
     */
    private boolean associateID(String idpID, String associatedID, String username, String tenantDomain,
                                String userStoreDomainName) {

        int tenantID = IdentityTenantUtil.getTenantId(tenantDomain);
        boolean associationCreated = false;
        try {
            UserProfileMgtDAO userProfileMgtDAO = UserProfileMgtDAO.getInstance();
            userProfileMgtDAO.createAssociation(tenantID, userStoreDomainName, username, idpID, associatedID);
            associationCreated = true;
        } catch (UserProfileException e) {
            String msg = "Error while creating association for user: " + username + " with federated IdP: " + idpID;
            log.error(msg, e);
        }
        return associationCreated;
    }
}
