/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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
 *
 */

package org.wso2.carbon.identity.conditional.auth.functions.opa.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.wso2.carbon.identity.application.authentication.framework.JsFunctionRegistry;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.conditional.auth.functions.opa.EvaluateOPAFunction;
import org.wso2.carbon.identity.conditional.auth.functions.opa.EvaluateOPAFunctionImpl;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;


/**
 * OSGi declarative services component which handle cookie related conditional auth functions.
 */

@Component(
        name = "identity.conditional.auth.functions.opa.component",
        immediate = true
)
public class OPAFunctionsServiceComponent {

    private static final Log LOG = LogFactory.getLog(OPAFunctionsServiceComponent.class);

    public static final String FUNC_EVALUATE_OPA = "evaluateOPA";


    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            JsFunctionRegistry jsFunctionRegistry = OPAFunctionsServiceHolder.getInstance().getJsFunctionRegistry();
            EvaluateOPAFunction evaluateOPA = new EvaluateOPAFunctionImpl();
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_EVALUATE_OPA, evaluateOPA);
        } catch (Throwable e) {
            LOG.error(e);
        }

    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        JsFunctionRegistry jsFunctionRegistry = OPAFunctionsServiceHolder.getInstance().getJsFunctionRegistry();
        if (jsFunctionRegistry != null) {
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_EVALUATE_OPA);
        }
    }

    @Reference(
            service = JsFunctionRegistry.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetJsFunctionRegistry"
    )
    public void setJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        OPAFunctionsServiceHolder.getInstance().setJsFunctionRegistry(jsFunctionRegistry);
    }

    public void unsetJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        OPAFunctionsServiceHolder.getInstance().setJsFunctionRegistry(null);
    }

    @Reference(
            name = "identityCoreInitializedEventService",
            service = IdentityCoreInitializedEvent.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityCoreInitializedEventService")
    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {

    /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {

    /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    @Reference(name = "claim.meta.mgt.service",
            service = ClaimMetadataManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetClaimMetaMgtService")
    protected void setClaimMetaMgtService(ClaimMetadataManagementService claimMetaMgtService) {

        OPAFunctionsServiceHolder.getInstance().setClaimMetadataManagementService(claimMetaMgtService);
    }

    protected void unsetClaimMetaMgtService(ClaimMetadataManagementService claimMetaMgtService) {

        OPAFunctionsServiceHolder.getInstance().setClaimMetadataManagementService(null);
    }
}
