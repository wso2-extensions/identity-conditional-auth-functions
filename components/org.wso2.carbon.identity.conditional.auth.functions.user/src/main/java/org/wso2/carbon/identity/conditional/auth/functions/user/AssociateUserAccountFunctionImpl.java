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
import org.wso2.carbon.user.core.util.UserCoreUtil;

public class AssociateUserAccountFunctionImpl implements AssociateUserAccountFunction {

    private static final Log LOG = LogFactory.getLog(AssociateUserAccountFunctionImpl.class);
    private static final String ALREADY_ASSOCIATED_MESSAGE = "UserAlreadyAssociated";

    @Override
    public void associateUserAccount(JsAuthenticatedUser localuser, JsAuthenticatedUser fuser, String fidp) {

        String userStoreDomainName = localuser.getWrapped().getUserStoreDomain();
        String username = localuser.getWrapped().getUserName();
        String subject = fuser.getWrapped().getAuthenticatedSubjectIdentifier();
        String tenantDomain = localuser.getWrapped().getTenantDomain();

        String usernameWithUserstoreDomain = UserCoreUtil.addDomainToName(username, userStoreDomainName);

        try {
            // start tenant flow
            FrameworkUtils.startTenantFlow(tenantDomain);
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(usernameWithUserstoreDomain);

            if (!StringUtils.isEmpty(fidp) && !StringUtils.isEmpty(subject)) {
                UserProfileAdmin userProfileAdmin = (UserProfileAdmin) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                        .getOSGiService(UserProfileAdmin.class);
                userProfileAdmin.associateID(fidp, subject);

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Associated local user: " + usernameWithUserstoreDomain + " in tenant: " +
                            tenantDomain + " to the federated subject : " + subject + " in IdP: " + fidp);
                }
            } else {
                LOG.error("Error while associating local user: " + usernameWithUserstoreDomain +
                        " in tenant: " + tenantDomain + " to the federated subject : " + subject + " in IdP: " + fidp);
            }
        } catch (UserProfileException e) {
            if (isUserAlreadyAssociated(e)) {
                LOG.info("An association already exists for user: " + subject + ". Skip association while JIT " +
                        "provisioning");
            } else {
                LOG.error("Error while associating local user: " + usernameWithUserstoreDomain +
                        " in tenant: " + tenantDomain + " to the federated subject : " + subject + " in IdP: " + fidp, e);
            }
        } finally {
            // end tenant flow
            FrameworkUtils.endTenantFlow();
        }
    }

    private boolean isUserAlreadyAssociated(UserProfileException e) {

        return e.getMessage() != null && e.getMessage().contains(ALREADY_ASSOCIATED_MESSAGE);
    }
}
