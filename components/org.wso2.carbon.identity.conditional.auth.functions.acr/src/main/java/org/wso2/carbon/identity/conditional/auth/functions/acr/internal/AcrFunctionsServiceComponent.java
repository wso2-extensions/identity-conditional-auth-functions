/*
 *  Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.conditional.auth.functions.acr.internal;

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
import org.wso2.carbon.identity.conditional.auth.functions.acr.SelectAcrFromFunction;
import org.wso2.carbon.registry.core.service.RegistryService;

@Component(
        name = "identity.conditional.auth.functions.acr.component",
        immediate = true
)
public class AcrFunctionsServiceComponent {

    private static final Log LOG = LogFactory.getLog(AcrFunctionsServiceComponent.class);

    public static final String JS_FUNC_SELECT_ACR_FROM = "selectAcrFrom";

    @Activate
    protected void activate(ComponentContext ctxt) {

        SelectAcrFromFunction selectAcrFromFunction = new SelectAcrFromFunction();
        JsFunctionRegistry jsFunctionRegistry = AcrFunctionsServiceHolder.getInstance().getJsFunctionRegistry();
        jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, JS_FUNC_SELECT_ACR_FROM, selectAcrFromFunction);
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        JsFunctionRegistry jsFunctionRegistry = AcrFunctionsServiceHolder.getInstance().getJsFunctionRegistry();
        if (jsFunctionRegistry != null) {
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, "selectAcrFrom");
        }
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
            LOG.debug("RegistryService is set in the conditional authentication acr functions bundle");
        }
        AcrFunctionsServiceHolder.getInstance().setRegistryService(registryService);
    }

    protected void unsetRegistryService(RegistryService registryService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("RegistryService is unset in the conditional authentication acr functions bundle");
        }
        AcrFunctionsServiceHolder.getInstance().setRegistryService(null);
    }

    @Reference(
            service = JsFunctionRegistry.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetJsFunctionRegistry"
    )
    public void setJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        AcrFunctionsServiceHolder.getInstance().setJsFunctionRegistry(jsFunctionRegistry);
    }

    public void unsetJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        AcrFunctionsServiceHolder.getInstance().setJsFunctionRegistry(null);
    }
}
