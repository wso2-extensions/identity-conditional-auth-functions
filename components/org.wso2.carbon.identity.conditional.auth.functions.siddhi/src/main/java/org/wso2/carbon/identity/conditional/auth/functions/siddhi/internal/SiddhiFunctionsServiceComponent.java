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

package org.wso2.carbon.identity.conditional.auth.functions.siddhi.internal;

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
import org.wso2.carbon.identity.conditional.auth.functions.siddhi.CallHTTPFunction;
import org.wso2.carbon.identity.conditional.auth.functions.siddhi.CallHTTPFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.siddhi.CallSiddhiFunction;
import org.wso2.carbon.identity.conditional.auth.functions.siddhi.CallSiddhiFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.siddhi.PublishToSiddhiFunction;
import org.wso2.carbon.identity.conditional.auth.functions.siddhi.PublishToSiddhiFunctionImpl;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * OSGi declarative services component which handled registration and unregistration of http requests related functions.
 */

@Component(
        name = "identity.conditional.auth.functions.siddhi.component",
        immediate = true
)
public class SiddhiFunctionsServiceComponent {

    private static final Log LOG = LogFactory.getLog(SiddhiFunctionsServiceComponent.class);
    public static final String FUNC_CALL_SIDDHI = "callSiddhi";
    public static final String FUNC_PUBLISH_SIDDHI = "publishToSiddhi";
    public static final String FUNC_CALL_HTTP = "callHTTP";

    @Activate
    protected void activate(ComponentContext ctxt) {

        JsFunctionRegistry jsFunctionRegistry = SiddhiFunctionsServiceHolder.getInstance().getJsFunctionRegistry();
        CallSiddhiFunction callSiddhi = new CallSiddhiFunctionImpl();
        jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_CALL_SIDDHI, callSiddhi);
        PublishToSiddhiFunction publishSiddhi = new PublishToSiddhiFunctionImpl();
        jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_PUBLISH_SIDDHI,
                publishSiddhi);
        CallHTTPFunction callHTTP = new CallHTTPFunctionImpl();
        jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_CALL_HTTP,
                callHTTP);
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        JsFunctionRegistry jsFunctionRegistry = SiddhiFunctionsServiceHolder.getInstance().getJsFunctionRegistry();
        if (jsFunctionRegistry != null) {
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_CALL_SIDDHI);
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_PUBLISH_SIDDHI);
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_CALL_HTTP);
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
            LOG.debug("RealmService is set in the conditional authentication siddhi functions bundle");
        }
        SiddhiFunctionsServiceHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("RealmService is unset in the conditional authentication siddhi functions bundle");
        }
        SiddhiFunctionsServiceHolder.getInstance().setRealmService(null);
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
            LOG.debug("RegistryService is set in the conditional authentication siddhi functions bundle");
        }
        SiddhiFunctionsServiceHolder.getInstance().setRegistryService(registryService);
    }

    protected void unsetRegistryService(RegistryService registryService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("RegistryService is unset in the conditional authentication siddhi functions bundle");
        }
        SiddhiFunctionsServiceHolder.getInstance().setRegistryService(null);
    }

    @Reference(
            service = JsFunctionRegistry.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetJsFunctionRegistry"
    )
    public void setJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        SiddhiFunctionsServiceHolder.getInstance().setJsFunctionRegistry(jsFunctionRegistry);
    }

    public void unsetJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        SiddhiFunctionsServiceHolder.getInstance().setJsFunctionRegistry(null);
    }

}
