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
import org.wso2.carbon.core.AbstractAdmin;
import org.wso2.carbon.identity.application.authentication.framework.JsFunctionRegistry;
import org.wso2.carbon.identity.conditional.auth.functions.user.AssociateUserAccountFunction;
import org.wso2.carbon.identity.conditional.auth.functions.user.AssociateUserAccountFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.user.GetAssociatedLocalUserFunction;
import org.wso2.carbon.identity.conditional.auth.functions.user.GetAssociatedLocalUserFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.user.HasRoleFunction;
import org.wso2.carbon.identity.conditional.auth.functions.user.HasRoleFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.user.LockUserAccountFunction;
import org.wso2.carbon.identity.conditional.auth.functions.user.LockUserAccountFunctionImpl;
import org.wso2.carbon.registry.core.service.RegistryService;
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

        HasRoleFunction hasRoleFunctionImpl = new HasRoleFunctionImpl();
        LockUserAccountFunction lockUserAccountFunctionImpl = new LockUserAccountFunctionImpl();
        AssociateUserAccountFunction associateUserAccountFunctionImpl = new AssociateUserAccountFunctionImpl();
        GetAssociatedLocalUserFunction getAssociatedLocalUserFunctionImpl = new GetAssociatedLocalUserFunctionImpl();
        JsFunctionRegistry jsFunctionRegistry = UserFunctionsServiceHolder.getInstance().getJsFunctionRegistry();
        jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "hasRole", hasRoleFunctionImpl);
        jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "lockUserAccount",
                lockUserAccountFunctionImpl);
        jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "associateUserAccount",
                associateUserAccountFunctionImpl);
        jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "getAssociatedLocalUser",
                getAssociatedLocalUserFunctionImpl);
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        JsFunctionRegistry jsFunctionRegistry = UserFunctionsServiceHolder.getInstance().getJsFunctionRegistry();
        if (jsFunctionRegistry != null) {
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "hasRole");
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "lockUserAccount");
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "associateUserAccount");
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "getAssociatedLocalUser");
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
            name = "registry.service",
            service = RegistryService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRegistryService"
    )
    protected void setRegistryService(RegistryService registryService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("RegistryService is set in the conditional authentication user functions bundle");
        }
        UserFunctionsServiceHolder.getInstance().setRegistryService(registryService);
    }

    protected void unsetRegistryService(RegistryService registryService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("RegistryService is unset in the conditional authentication user functions bundle");
        }
        UserFunctionsServiceHolder.getInstance().setRegistryService(null);
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
            service = AbstractAdmin.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetAbstractAdmin"
    )
    protected void setAbstractAdmin(AbstractAdmin abstractAdmin) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("AbstractAdmin is set in the conditional authentication user functions bundle");
        }
        UserFunctionsServiceHolder.getInstance().setAbstractAdmin(abstractAdmin);
    }

    protected void unsetAbstractAdmin(AbstractAdmin abstractAdmin) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("AbstractAdmin is unset in the conditional authentication user functions bundle");
        }
        UserFunctionsServiceHolder.getInstance().setAbstractAdmin(null);
    }

}
