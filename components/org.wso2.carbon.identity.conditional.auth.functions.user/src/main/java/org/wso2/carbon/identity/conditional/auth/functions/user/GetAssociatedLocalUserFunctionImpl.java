/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsWrapperFactoryProvider;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileAdmin;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileException;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.Map;

public class GetAssociatedLocalUserFunctionImpl implements GetAssociatedLocalUserFunction {

    private static final Log LOG = LogFactory.getLog(GetAssociatedLocalUserFunctionImpl.class);

    @Override
    @HostAccess.Export
    public JsAuthenticatedUser getAssociatedLocalUser(JsAuthenticatedUser federatedUser) {

        if (!federatedUser.getWrapped().isFederatedUser()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("User " + federatedUser.getWrapped().getUserName() + " is not a federated user.");
            }
            return null;
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
                externalSubject = federatedUser.getWrapped().getAuthenticatedSubjectIdentifier();
            }
        } catch (IdentityProviderManagementException e) {
            String msg =
                    "Error while retrieving identity provider by name: " + externalIdpName;
            LOG.error(msg, e);
        }
        String associatedID = null;

        try {
            // Start tenant flow.
            FrameworkUtils.startTenantFlow(tenantDomain);
            UserProfileAdmin userProfileAdmin = UserProfileAdmin.getInstance();
            associatedID = userProfileAdmin.getNameAssociatedWith(externalIdpName, externalSubject);
        } catch (UserProfileException e) {
            LOG.error("Error while getting associated local user ID for " + externalSubject, e);
        } finally {
            // end tenant flow
            FrameworkUtils.endTenantFlow();
        }
        if (StringUtils.isNotBlank(associatedID)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("User " + federatedUser.getWrapped().getUserName() + " has an associated local account as " +
                        associatedID + ". Hence continuing as " + associatedID);
            }
            String fullQualifiedAssociatedUserId = FrameworkUtils.prependUserStoreDomainToName(UserCoreUtil
                    .addTenantDomainToEntry(associatedID, tenantDomain));
            AuthenticatedUser authenticatedUser =
                    AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(fullQualifiedAssociatedUserId);
            return (JsAuthenticatedUser) JsWrapperFactoryProvider.getInstance().getWrapperFactory().
                    createJsAuthenticatedUser(authenticatedUser);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("User " + federatedUser.getWrapped().getUserName() + " doesn't have an associated local" +
                        " account.");
            }
            return null;
        }
    }
}
