/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

/**
 * Function to update user password.
 */
public class UpdateUserPasswordFunctionImpl implements UpdateUserPasswordFunction {

    @Override
    public void updateUserPassword(JsAuthenticatedUser user, String newPassword) throws FrameworkException {

        if (user == null) {
            throw new FrameworkException("User is not defined.");
        }
        if (StringUtils.isBlank(newPassword)) {
            throw new FrameworkException("The password cannot be empty.");
        }

        try {
            if (user.getWrapped() != null) {
                String tenantDomain = user.getWrapped().getTenantDomain();
                String userStoreDomain = user.getWrapped().getUserStoreDomain();
                String username = user.getWrapped().getUserName();
                UserRealm userRealm = Utils.getUserRealm(tenantDomain);

                if (userRealm != null) {
                    UserStoreManager userStoreManager = Utils.getUserStoreManager(
                            tenantDomain, userRealm, userStoreDomain);
                    userStoreManager.updateCredentialByAdmin(username, newPassword);
                } else {
                    throw new FrameworkException(String.format("Unable to find user realm for the user: %s " +
                            "in tenant: %s", username, tenantDomain));
                }
            } else {
                throw new FrameworkException("Unable to get wrapped content for the user.");
            }
        } catch (UserStoreException e) {
            throw new FrameworkException("Error while updating the user password.", e);
        }
    }
}
