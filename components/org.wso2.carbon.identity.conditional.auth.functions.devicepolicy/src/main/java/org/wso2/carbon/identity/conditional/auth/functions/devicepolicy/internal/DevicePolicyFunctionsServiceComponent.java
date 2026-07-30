/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.devicepolicy.internal;

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
import org.wso2.carbon.identity.conditional.auth.functions.devicepolicy.DevicePolicyComplianceFunction;
import org.wso2.carbon.identity.conditional.auth.functions.devicepolicy.DevicePolicyComplianceFunctionImpl;
import org.wso2.carbon.identity.device.policy.api.service.DevicePolicyEvaluator;

/**
 * OSGi declarative services component which handles registration and de-registration of the
 * device policy compliance conditional auth function.
 */
@Component(
        name = "identity.conditional.auth.functions.devicepolicy",
        immediate = true
)
public class DevicePolicyFunctionsServiceComponent {

    private static final Log LOG = LogFactory.getLog(DevicePolicyFunctionsServiceComponent.class);
    private static final String FUNCTION_NAME = "isDevicePolicyCompliant";

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            DevicePolicyComplianceFunction devicePolicyComplianceFunction = new DevicePolicyComplianceFunctionImpl();
            JsFunctionRegistry jsFunctionRegistry = DevicePolicyFunctionsServiceHolder.getInstance()
                    .getJsFunctionRegistry();
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNCTION_NAME,
                    devicePolicyComplianceFunction);
        } catch (Throwable e) {
            LOG.error("Error occurred during device policy conditional auth function bundle activation.", e);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Device policy conditional auth function component is activated.");
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        JsFunctionRegistry jsFunctionRegistry = DevicePolicyFunctionsServiceHolder.getInstance()
                .getJsFunctionRegistry();
        if (jsFunctionRegistry != null) {
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNCTION_NAME);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Device policy conditional auth function component is deactivated.");
        }
    }

    @Reference(
            service = JsFunctionRegistry.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetJsFunctionRegistry"
    )
    protected void setJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        DevicePolicyFunctionsServiceHolder.getInstance().setJsFunctionRegistry(jsFunctionRegistry);
    }

    protected void unsetJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        DevicePolicyFunctionsServiceHolder.getInstance().setJsFunctionRegistry(null);
    }

    @Reference(
            name = "device.policy.evaluator",
            service = DevicePolicyEvaluator.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetDevicePolicyEvaluator"
    )
    protected void setDevicePolicyEvaluator(DevicePolicyEvaluator devicePolicyEvaluator) {

        DevicePolicyFunctionsServiceHolder.getInstance().setDevicePolicyEvaluator(devicePolicyEvaluator);
    }

    protected void unsetDevicePolicyEvaluator(DevicePolicyEvaluator devicePolicyEvaluator) {

        DevicePolicyFunctionsServiceHolder.getInstance().setDevicePolicyEvaluator(null);
    }
}
