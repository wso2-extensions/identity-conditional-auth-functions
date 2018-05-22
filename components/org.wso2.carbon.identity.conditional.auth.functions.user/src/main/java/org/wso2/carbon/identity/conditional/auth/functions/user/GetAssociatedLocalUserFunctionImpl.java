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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileAdmin;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileException;

public class GetAssociatedLocalUserFunctionImpl implements GetAssociatedLocalUserFunction {

    private static final Log LOG = LogFactory.getLog(GetAssociatedLocalUserFunctionImpl.class);

    @Override
    public String getAssociatedLocalUser(JsAuthenticatedUser fuser, String identityProvider) {

        String originalExternalIdpSubjectValueForThisStep = fuser.getWrapped().getAuthenticatedSubjectIdentifier();
        String associatedID = null;

        // start tenant flow
        FrameworkUtils.startTenantFlow(fuser.getWrapped().getTenantDomain());
        UserProfileAdmin userProfileAdmin = (UserProfileAdmin) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getOSGiService(UserProfileAdmin.class);
        try {
            associatedID = userProfileAdmin.getNameAssociatedWith(identityProvider,
                    originalExternalIdpSubjectValueForThisStep);

        } catch (UserProfileException e) {
            LOG.error("Error while getting associated local user ID for "
                    + originalExternalIdpSubjectValueForThisStep, e);
        } finally {
            // end tenant flow
            FrameworkUtils.endTenantFlow();
        }
        if (StringUtils.isNotBlank(associatedID)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("User " + fuser.getWrapped().getUserName() +
                        " has an associated account as " + associatedID + ". Hence continuing as " +
                        associatedID);
            }
            return associatedID;
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("User " + fuser.getWrapped().getUserName() +
                        " doesn't have an associated" +
                        " account. Hence continuing as the same user.");

            }
            return fuser.getWrapped().getUserName();
        }
    }
}
