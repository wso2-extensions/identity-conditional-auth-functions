/**
 * Copyright (c) 2022, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.user;

import com.wso2.identity.asgardeo.realm.config.builder.AsgardeoRealmUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.conditional.auth.functions.user.internal.UserFunctionsServiceHolder;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_ID;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.USER_TENANT_DOMAIN;
import static org.wso2.carbon.user.core.UserCoreConstants.DOMAIN_SEPARATOR;
import static org.wso2.carbon.user.core.UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

public class HandleAsgardeoSSOFunctionImpl implements HandleAsgardeoSSOFunction {

    private static final Log log = LogFactory.getLog(HandleAsgardeoSSOFunctionImpl.class);

    @Override
    public void handleAsgardeoSSO(JsAuthenticationContext context) throws AuthenticationFailedException {

        if (context.getWrapped().isLogoutRequest()) {
            return;
        }

        // Initial request.
        if (MapUtils.isEmpty(context.getWrapped().getPreviousAuthenticatedIdPs())) {
            AuthenticatedUser subject = getAuthenticationUserFromStepOne(context.getWrapped());
            completeAuthenticationFlow(context.getWrapped(), subject);
            return;
        }

        AuthenticatedUser subject = getAuthenticationUserFromStepOne(context.getWrapped());
        if (isAsgardeoUser(subject)) {
            if (log.isDebugEnabled()) {
                log.debug("The " + subject.toFullQualifiedUsername() + " is an Asgardeo user. SSO to WSO2 app " +
                        "with the identifier of the super tenant.");
            }
            try {
                String asgardeoUserStoreDomainName = AsgardeoRealmUtils.getAsgardeoUserStoreDomainName();
                AuthenticatedUser user = new AuthenticatedUser();
                user.setUserName(subject.getUserName());
                user.setTenantDomain(SUPER_TENANT_DOMAIN_NAME);
                user.setUserStoreDomain(asgardeoUserStoreDomainName);
                user.setUserId(subject.getUserId());
                context.getWrapped().setProperty(USER_TENANT_DOMAIN, SUPER_TENANT_DOMAIN_NAME);
                completeAuthenticationFlow(context.getWrapped(), user);
            } catch (UserIdNotFoundException e) {
                throw new AuthenticationFailedException("User id not found for user: " + subject.getLoggableUserId(),
                        e);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("The " + subject.toFullQualifiedUsername() + " is a normal user. " +
                        "SSO to WSO2 app with the same identifier.");
            }
            completeAuthenticationFlow(context.getWrapped(), subject);
        }
    }

    private boolean isAsgardeoUser(AuthenticatedUser subject) throws AuthenticationFailedException {

        try {
            RealmService realmService = UserFunctionsServiceHolder.getInstance().getRealmService();
            String asgardeoUserStoreDomainName = AsgardeoRealmUtils.getAsgardeoUserStoreDomainName();
            String userStoreDomain = subject.getUserStoreDomain();
            if (StringUtils.isBlank(userStoreDomain) || asgardeoUserStoreDomainName.equalsIgnoreCase(userStoreDomain) ||
                    PRIMARY_DEFAULT_DOMAIN_NAME.equalsIgnoreCase(userStoreDomain)) {
                UserStoreManager userStoreManager = realmService.getTenantUserRealm(SUPER_TENANT_ID).
                        getUserStoreManager();
                return userStoreManager.isExistingUser(asgardeoUserStoreDomainName + DOMAIN_SEPARATOR +
                        subject.getUserName());
            }
            return false;
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error occurred while checking " + subject.getUserName() +
                    " is an Asgardeo User", e);
        }
    }

    private void completeAuthenticationFlow(AuthenticationContext context, AuthenticatedUser subject)
            throws AuthenticationFailedException {

        AuthenticatedUser user = null;
        try {
            user = new AuthenticatedUser();
            user.setUserName(subject.getUserName());
            user.setUserStoreDomain(subject.getUserStoreDomain());
            user.setTenantDomain(subject.getTenantDomain());
            user.setUserId(subject.getUserId());
            context.setSubject(user);
        } catch (UserIdNotFoundException e) {
            throw new AuthenticationFailedException("User id not found for user: " + subject.getLoggableUserId(),
                    e);
        }

        Map<String, String> identifierParams = new HashMap<>();
        identifierParams.put(FrameworkConstants.JSAttributes.JS_OPTIONS_USERNAME, user.toFullQualifiedUsername());
        Map<String, Map<String, String>> contextParams = new HashMap<>();
        contextParams.put(FrameworkConstants.JSAttributes.JS_COMMON_OPTIONS, identifierParams);
        context.addAuthenticatorParams(contextParams);
    }

    private AuthenticatedUser getAuthenticationUserFromStepOne(AuthenticationContext context)
            throws AuthenticationFailedException {

        if (context.getSequenceConfig() != null && context.getSequenceConfig().getStepMap() != null
                && context.getSequenceConfig().getStepMap().size() > 0
                && context.getSequenceConfig().getStepMap().get(1) != null
                && context.getSequenceConfig().getStepMap().get(1).getAuthenticatedUser() != null) {
            return context.getSequenceConfig().getStepMap().get(1).getAuthenticatedUser();
        }
        throw new AuthenticationFailedException("Error occurred getting the user from step one.");
    }
}
