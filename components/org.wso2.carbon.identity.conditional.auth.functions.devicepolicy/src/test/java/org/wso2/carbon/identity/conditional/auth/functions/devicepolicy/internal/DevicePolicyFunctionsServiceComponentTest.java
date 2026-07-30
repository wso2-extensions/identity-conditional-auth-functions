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

import org.mockito.Mock;
import org.osgi.service.component.ComponentContext;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.JsFunctionRegistry;
import org.wso2.carbon.identity.conditional.auth.functions.devicepolicy.DevicePolicyComplianceFunction;
import org.wso2.carbon.identity.device.policy.api.service.DevicePolicyEvaluator;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.MockitoAnnotations.initMocks;

/**
 * Test class for DevicePolicyFunctionsServiceComponent.
 */
public class DevicePolicyFunctionsServiceComponentTest {

    private static final String FUNCTION_NAME = "isDevicePolicyCompliant";

    @Mock
    private JsFunctionRegistry jsFunctionRegistry;
    @Mock
    private DevicePolicyEvaluator devicePolicyEvaluator;
    @Mock
    private ComponentContext componentContext;

    private DevicePolicyFunctionsServiceComponent serviceComponent;

    @BeforeMethod
    public void setUp() {

        initMocks(this);
        serviceComponent = new DevicePolicyFunctionsServiceComponent();
    }

    @AfterMethod
    public void tearDown() {

        DevicePolicyFunctionsServiceHolder.getInstance().setJsFunctionRegistry(null);
        DevicePolicyFunctionsServiceHolder.getInstance().setDevicePolicyEvaluator(null);
    }

    @Test
    public void testSetAndUnsetJsFunctionRegistry() {

        serviceComponent.setJsFunctionRegistry(jsFunctionRegistry);
        Assert.assertSame(DevicePolicyFunctionsServiceHolder.getInstance().getJsFunctionRegistry(),
                jsFunctionRegistry);

        serviceComponent.unsetJsFunctionRegistry(jsFunctionRegistry);
        Assert.assertNull(DevicePolicyFunctionsServiceHolder.getInstance().getJsFunctionRegistry());
    }

    @Test
    public void testSetAndUnsetDevicePolicyEvaluator() {

        serviceComponent.setDevicePolicyEvaluator(devicePolicyEvaluator);
        Assert.assertSame(DevicePolicyFunctionsServiceHolder.getInstance().getDevicePolicyEvaluator(),
                devicePolicyEvaluator);

        serviceComponent.unsetDevicePolicyEvaluator(devicePolicyEvaluator);
        Assert.assertNull(DevicePolicyFunctionsServiceHolder.getInstance().getDevicePolicyEvaluator());
    }

    @Test
    public void testActivateRegistersFunction() {

        serviceComponent.setJsFunctionRegistry(jsFunctionRegistry);
        serviceComponent.activate(componentContext);

        verify(jsFunctionRegistry).register(eq(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER), eq(FUNCTION_NAME),
                any(DevicePolicyComplianceFunction.class));
    }

    @Test
    public void testActivateWithoutRegistryDoesNotFail() {

        // The registry is a mandatory reference, but activation must not propagate failures if it is unavailable.
        serviceComponent.activate(componentContext);
    }

    @Test
    public void testDeactivateDeRegistersFunction() {

        serviceComponent.setJsFunctionRegistry(jsFunctionRegistry);
        serviceComponent.deactivate(componentContext);

        verify(jsFunctionRegistry).deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNCTION_NAME);
    }

    @Test
    public void testDeactivateWithoutRegistryDoesNotFail() {

        JsFunctionRegistry unboundRegistry = mock(JsFunctionRegistry.class);

        serviceComponent.deactivate(componentContext);

        verifyNoInteractions(unboundRegistry);
    }
}
