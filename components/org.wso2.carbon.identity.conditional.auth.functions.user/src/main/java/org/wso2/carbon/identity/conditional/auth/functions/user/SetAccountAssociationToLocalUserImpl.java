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
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileException;
import org.wso2.carbon.identity.user.profile.mgt.dao.UserProfileMgtDAO;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;

import java.util.Map;

public class SetAccountAssociationToLocalUserImpl implements SetAccountAssociationToLocalUser {

    private static final Log log = LogFactory.getLog(SetAccountAssociationToLocalUserImpl.class);

    @Override
    public void doAssociationWithLocalUser(JsAuthenticatedUser federatedUser, String username, String tenantDomain,
                                           String userStoreDomainName) {

        String federatedIdpName = null;
        try {
            if (federatedUser != null) {
                if (federatedUser.getWrapped().isFederatedUser()) {
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
                        associateID(externalIdpName, externalSubject, username, tenantDomain, userStoreDomainName);
                    } else {
                        log.warn(" Authenticated user or External IDP may be null " + " Authenticated User: " +
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
    }

    /**
     * @param idpID               external IDP name
     * @param associatedID        external authenticated user
     * @param username            local user name
     * @param tenantDomain        tenant domain
     * @param userStoreDomainName user store domain name
     */
    private void associateID(String idpID, String associatedID, String username, String tenantDomain,
                             String userStoreDomainName) {

        int tenantID = IdentityTenantUtil.getTenantId(tenantDomain);
        try {
            UserProfileMgtDAO userProfileMgtDAO = UserProfileMgtDAO.getInstance();
            userProfileMgtDAO.createAssociation(tenantID, userStoreDomainName, username, idpID, associatedID);
        } catch (UserProfileException e) {
            String msg = "Error while creating association for user: " + username + " with federated IdP: " + "" + idpID;
            log.error(msg, e);
        }
    }
}
