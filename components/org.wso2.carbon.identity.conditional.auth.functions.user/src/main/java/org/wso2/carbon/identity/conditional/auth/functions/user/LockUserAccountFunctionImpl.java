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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.recovery.IdentityRecoveryConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.util.HashMap;

import static org.wso2.carbon.identity.conditional.auth.functions.user.utils.AuthFunctionsUtil.getUserRealm;
import static org.wso2.carbon.identity.conditional.auth.functions.user.utils.AuthFunctionsUtil.getUserStoreManager;

/**
 * Implementation of the {@link LockUserAccountFunction}
 */
public class LockUserAccountFunctionImpl implements LockUserAccountFunction {

    private static final Log LOG = LogFactory.getLog(LockUserAccountFunctionImpl.class);

    @Override
    public void lockUserAccount(JsAuthenticatedUser user) {

        String tenantDomain = user.getWrapped().getTenantDomain();
        String userStoreDomain = user.getWrapped().getUserStoreDomain();
        String userName = user.getWrapped().getUserName();
        try {
            UserRealm userRealm = getUserRealm(user.getWrapped().getTenantDomain());
            if (userRealm != null) {
                UserStoreManager userStoreManager = getUserStoreManager(tenantDomain, userRealm, userStoreDomain);
                setUserClaim(IdentityRecoveryConstants.ACCOUNT_LOCKED_CLAIM, Boolean.TRUE.toString(), userStoreManager,
                        user.getWrapped());
                LOG.info("User account locked: " + userName);
            }
        } catch (FrameworkException e) {
            LOG.error("Error in evaluating the function ", e);
        }
    }

    private void setUserClaim(String claimName, String claimValue, UserStoreManager userStoreManager, User user) {

        HashMap<String, String> userClaims = new HashMap<>();
        userClaims.put(claimName, claimValue);
        try {
            userStoreManager.setUserClaimValues(user.getUserName(), userClaims, null);
        } catch (UserStoreException e) {
            LOG.error("Error while setting user claim value :" + user.getUserName(), e);
        }

    }
}
