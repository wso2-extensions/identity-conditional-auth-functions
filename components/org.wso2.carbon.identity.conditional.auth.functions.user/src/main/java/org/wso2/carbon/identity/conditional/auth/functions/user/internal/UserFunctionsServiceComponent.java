/*
 *  Copyright (c) 2018, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.conditional.auth.functions.user.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.JsFunctionRegistry;
import org.wso2.carbon.identity.application.authentication.framework.UserSessionManagementService;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.conditional.auth.functions.user.AssignUserRolesFunction;
import org.wso2.carbon.identity.conditional.auth.functions.user.AssignUserRolesFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.user.AssignUserRolesV2Function;
import org.wso2.carbon.identity.conditional.auth.functions.user.AssignUserRolesV2FunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.user.CheckSessionExistenceFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.user.GetAuthenticatedApplicationsV2FunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.user.HasAnyOfTheRolesV2Function;
import org.wso2.carbon.identity.conditional.auth.functions.user.HasAnyOfTheRolesV2FunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.user.MicrosoftEmailVerificationFunction;
import org.wso2.carbon.identity.conditional.auth.functions.user.MicrosoftEmailVerificationFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.user.GetAssociatedLocalUserFunction;
import org.wso2.carbon.identity.conditional.auth.functions.user.GetAssociatedLocalUserFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.user.GetUserSessionsFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.user.IsMemberOfAnyOfGroupsFunction;
import org.wso2.carbon.identity.conditional.auth.functions.user.IsMemberOfAnyOfGroupsFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.user.HasAnyOfTheRolesFunction;
import org.wso2.carbon.identity.conditional.auth.functions.user.HasAnyOfTheRolesFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.user.HasRoleFunction;
import org.wso2.carbon.identity.conditional.auth.functions.user.HasRoleFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.user.IsAnyOfTheRolesAssignedToUserFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.user.PromptIdentifierFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.user.RemoveUserRolesFunction;
import org.wso2.carbon.identity.conditional.auth.functions.user.RemoveUserRolesFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.user.RemoveUserRolesV2Function;
import org.wso2.carbon.identity.conditional.auth.functions.user.RemoveUserRolesV2FunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.user.TerminateUserSessionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.user.SetAccountAssociationToLocalUserImpl;
import org.wso2.carbon.identity.conditional.auth.functions.user.SetAccountAssociationToLocalUser;
import org.wso2.carbon.identity.conditional.auth.functions.user.UpdateUserPasswordFunction;
import org.wso2.carbon.identity.conditional.auth.functions.user.UpdateUserPasswordFunctionImpl;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * OSGi declarative services component which handles registration and de-registration of user conditional auth
 * functions.
 */
@Component(
        name = "identity.conditional.auth.functions.user.component",
        immediate = true
)
public class UserFunctionsServiceComponent {

    private static final Log LOG = LogFactory.getLog(UserFunctionsServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            HasRoleFunction hasRoleFunctionImpl = new HasRoleFunctionImpl();
            IsMemberOfAnyOfGroupsFunction isMemberOfAnyOfGroupsFunctionImpl = new IsMemberOfAnyOfGroupsFunctionImpl();
            HasAnyOfTheRolesFunction hasAnyOfTheRolesFunctionImpl = new HasAnyOfTheRolesFunctionImpl();
            AssignUserRolesV2Function assignUserRolesV2FunctionImpl = new AssignUserRolesV2FunctionImpl();
            HasAnyOfTheRolesV2Function hasAnyOfTheRolesV2FunctionImpl = new HasAnyOfTheRolesV2FunctionImpl();
            RemoveUserRolesV2Function removeUserRolesV2FunctionImpl = new RemoveUserRolesV2FunctionImpl();
            AssignUserRolesFunction assignUserRolesFunctionImpl = new AssignUserRolesFunctionImpl();
            RemoveUserRolesFunction removeUserRolesFunctionImpl = new RemoveUserRolesFunctionImpl();
            GetAssociatedLocalUserFunction getAssociatedLocalUserFunctionImpl = new GetAssociatedLocalUserFunctionImpl();
            SetAccountAssociationToLocalUser setAccountAssociationToLocalUserImpl = new SetAccountAssociationToLocalUserImpl();
            MicrosoftEmailVerificationFunction microsoftEmailVerificationFunction = new MicrosoftEmailVerificationFunctionImpl();
            UpdateUserPasswordFunction updateUserPasswordFunction = new UpdateUserPasswordFunctionImpl();

            JsFunctionRegistry jsFunctionRegistry = UserFunctionsServiceHolder.getInstance().getJsFunctionRegistry();
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "hasRole", hasRoleFunctionImpl);
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "hasAnyOfTheRoles",
                    hasAnyOfTheRolesFunctionImpl);
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "hasAnyOfTheRolesV2",
                    hasAnyOfTheRolesV2FunctionImpl);
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "isMemberOfAnyOfGroups",
                    isMemberOfAnyOfGroupsFunctionImpl);
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "assignUserRoles",
                    assignUserRolesFunctionImpl);
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "assignUserRolesV2",
                    assignUserRolesV2FunctionImpl);
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "removeUserRoles",
                    removeUserRolesFunctionImpl);
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "removeUserRolesV2",
                    removeUserRolesV2FunctionImpl);
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "promptIdentifierForStep",
                    new PromptIdentifierFunctionImpl());
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "checkSessionExistence",
                    new CheckSessionExistenceFunctionImpl());
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "getAssociatedLocalUser",
                    getAssociatedLocalUserFunctionImpl);
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "getUserSessions",
                    new GetUserSessionsFunctionImpl());
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "terminateUserSession",
                    new TerminateUserSessionImpl());
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "doAssociationWithLocalUser",
                    setAccountAssociationToLocalUserImpl);
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "isAnyOfTheRolesAssignedToUser",
                    new IsAnyOfTheRolesAssignedToUserFunctionImpl());
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "getAuthenticatedApplications",
                    new GetAuthenticatedApplicationsV2FunctionImpl());
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "checkMicrosoftEmailVerification",
                    microsoftEmailVerificationFunction);
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "updateUserPassword",
                    updateUserPasswordFunction);
        } catch (Throwable e) {
            LOG.error("Error occurred during conditional authentication user functions bundle activation. ", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        JsFunctionRegistry jsFunctionRegistry = UserFunctionsServiceHolder.getInstance().getJsFunctionRegistry();
        if (jsFunctionRegistry != null) {
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "hasRole");
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "hasAnyOfTheRoles");
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "hasAnyOfTheRolesV2");
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "isMemberOfAnyOfGroups");
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "promptIdentifierForStep");
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "checkSessionExistence");
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "assignUserRoles");
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "removeUserRoles");
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "getAssociatedLocalUser");
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "getUserSessions");
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "terminateUserSession");
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "doAssociationWithLocalUser");
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "isAnyOfTheRolesAssignedToUser");
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "checkMicrosoftEmailVerification");
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "updateUserPassword");
        }
    }

    @Reference(
            name = "user.realmservice.default",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("RealmService is set in the conditional authentication user functions bundle");
        }
        UserFunctionsServiceHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("RealmService is unset in the conditional authentication user functions bundle");
        }
        UserFunctionsServiceHolder.getInstance().setRealmService(null);
    }

    @Reference(
            name = "org.wso2.carbon.identity.application.authentication.framework.UserSessionManagementService",
            service = UserSessionManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetUserSessionManagementService"
    )
    protected void setUserSessionManagementService(UserSessionManagementService userSessionManagementService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("UserSessionManagementService is set in the conditional authentication user functions bundle");
        }
        UserFunctionsServiceHolder.getInstance().setUserSessionManagementService(userSessionManagementService);
    }

    protected void unsetUserSessionManagementService(UserSessionManagementService userSessionManagementService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("UserSessionManagementService is unset in the conditional authentication user functions bundle");
        }
        UserFunctionsServiceHolder.getInstance().setUserSessionManagementService(null);
    }

    @Reference(
            service = JsFunctionRegistry.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetJsFunctionRegistry"
    )
    public void setJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        UserFunctionsServiceHolder.getInstance().setJsFunctionRegistry(jsFunctionRegistry);
    }

    public void unsetJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        UserFunctionsServiceHolder.getInstance().setJsFunctionRegistry(null);
    }

    @Reference(
            name = "org.wso2.carbon.idp.mgt.IdpManager",
            service = IdpManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityProviderManagementService"
    )
    protected void setIdentityProviderManagementService(IdpManager idpManager) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("IdpManager service is set in the conditional authentication user functions bundle");
        }
        UserFunctionsServiceHolder.getInstance().setIdentityProviderManagementService(idpManager);
    }

    protected void unsetIdentityProviderManagementService(IdpManager idpManager) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("IdpManager service is unset in the conditional authentication user functions bundle");
        }
        UserFunctionsServiceHolder.getInstance().setIdentityProviderManagementService(null);
    }

    @Reference(name = "application.mgt.service",
            service = ApplicationManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetApplicationManagementService")
    protected void setApplicationManagementService(ApplicationManagementService applicationManagementService) {

        UserFunctionsServiceHolder.getInstance().setApplicationManagementService(applicationManagementService);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Application management service is set in the conditional authentication user functions bundle.");
        }
    }

    protected void unsetApplicationManagementService(ApplicationManagementService applicationManagementService) {

        UserFunctionsServiceHolder.getInstance().setApplicationManagementService(null);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Application management service is unset in the conditional authentication user functions " +
                    "bundle");
        }
    }

    @Reference(
            name = "role.management.service.v2",
            service = RoleManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRoleManagementService")
    protected void setRoleManagementService(RoleManagementService roleManagementService) {

        UserFunctionsServiceHolder.getInstance().setRoleManagementService(roleManagementService);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Role management service is set in the conditional authentication user functions bundle.");
        }
    }

    protected void unsetRoleManagementService(RoleManagementService roleManagementService) {

        UserFunctionsServiceHolder.getInstance().setRoleManagementService(null);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Role management service is unset in the conditional authentication user functions bundle");
        }
    }
}
