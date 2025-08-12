/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileAdmin;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileException;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;

import java.util.Map;

public class RemoveAssociatedLocalUserFunctionImpl implements RemoveAssociatedLocalUserFunction {

    private static final Log LOG = LogFactory.getLog(RemoveAssociatedLocalUserFunctionImpl.class);

    @Override
    @HostAccess.Export
    public boolean removeAssociatedLocalUser(JsAuthenticatedUser federatedUser) {

        if (!federatedUser.getWrapped().isFederatedUser()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("User " + federatedUser.getWrapped().getUserName() + " is not a federated user.");
            }
            return false;
        }

        String tenantDomain = federatedUser.getWrapped().getTenantDomain();
        String externalIdpName = federatedUser.getWrapped().getFederatedIdPName();
        String externalSubject = null;

        try {
            String userIdClaimURI = Utils.getUserIdClaimURI(externalIdpName, tenantDomain);
            if (StringUtils.isNotEmpty(userIdClaimURI) &&
                    MapUtils.isNotEmpty(federatedUser.getWrapped().getUserAttributes())) {
                externalSubject = federatedUser.getWrapped().getUserAttributes().entrySet().stream().filter(
                        userAttribute -> userAttribute.getKey().getRemoteClaim().getClaimUri()
                                .equals(userIdClaimURI))
                        .map(Map.Entry::getValue)
                        .findFirst()
                        .orElse(null);
            } else {
                if (StringUtils.isEmpty(userIdClaimURI) && LOG.isDebugEnabled()) {
                    LOG.debug("No mapping found for userIdClaimURI in the IDP.");
                }
                externalSubject = federatedUser.getWrapped().getAuthenticatedSubjectIdentifier();
            }
        } catch (IdentityProviderManagementException e) {
            String msg =
                    "Error while retrieving identity provider by name: " + externalIdpName;
            LOG.error(msg, e);
        }

        String associatedID = null;
        UserProfileAdmin userProfileAdmin = UserProfileAdmin.getInstance();

        try {
            // Start tenant flow.
            FrameworkUtils.startTenantFlow(tenantDomain);
            associatedID = userProfileAdmin.getNameAssociatedWith(externalIdpName, externalSubject);
        } catch (UserProfileException e) {
            LOG.error("Error while getting associated local user ID for " + externalSubject, e);
        } finally {
            FrameworkUtils.endTenantFlow();
        }

        if (StringUtils.isBlank(associatedID)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("User " + federatedUser.getWrapped().getUserName() + " doesn't have an associated local" +
                        " account.");
            }
            return false;
        }

        // Remove association with local user as an association exists.
        try {
            userProfileAdmin.removeAssociateIDForUser(associatedID, externalIdpName, externalSubject);
            if (LOG.isDebugEnabled()) {
                LOG.debug("User association removed successfully.");
            }
            return true;
        } catch (UserProfileException e) {
            String msg = "Error while removing association for user: " + federatedUser.getWrapped().getUserName()
                    + " with federated IdP: " + externalIdpName;
            LOG.error(msg, e);
        }
        return false;
    }
}
