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
import org.wso2.carbon.identity.conditional.auth.functions.user.utils.AuthFunctionsUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.util.Arrays;

/**
 * Implementation of the {@link HasRoleFunction}
 */
public class HasRoleFunctionImpl implements HasRoleFunction {

    private static final Log LOG = LogFactory.getLog(HasRoleFunctionImpl.class);

    @Override
    public boolean hasRole(JsAuthenticatedUser user, String roleName) {

        boolean result = false;

        String tenantDomain = user.getWrapped().getTenantDomain();
        String userStoreDomain = user.getWrapped().getUserStoreDomain();
        String username = user.getWrapped().getUserName();
        try {
            UserRealm userRealm = AuthFunctionsUtil.getUserRealm(user.getWrapped().getTenantDomain());
            if (userRealm != null) {
                UserStoreManager userStore = AuthFunctionsUtil.getUserStoreManager(tenantDomain, userRealm, userStoreDomain);
                if (userStore != null) {
                    result = Arrays.stream(userStore.getRoleListOfUser(username)).anyMatch(r -> r.equals(roleName));
                }
            }
        } catch (FrameworkException e) {
            LOG.error("Error in evaluating the function ", e);
        } catch (UserStoreException e) {
            LOG.error("Error in getting user from store at the function ", e);
        }

        return result;
    }

}
