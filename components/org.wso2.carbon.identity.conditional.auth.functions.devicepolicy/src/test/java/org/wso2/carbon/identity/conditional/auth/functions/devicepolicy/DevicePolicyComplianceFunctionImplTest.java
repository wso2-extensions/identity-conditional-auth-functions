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

package org.wso2.carbon.identity.conditional.auth.functions.devicepolicy;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.script.AuthenticationScriptConfig;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.central.log.mgt.internal.CentralLogMgtServiceComponentHolder;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.conditional.auth.functions.devicepolicy.internal.DevicePolicyFunctionsServiceHolder;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsSequenceHandlerAbstractTest;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsTestException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.device.policy.api.exception.DevicePolicyClientException;
import org.wso2.carbon.identity.device.policy.api.exception.DevicePolicyServerException;
import org.wso2.carbon.identity.device.policy.api.model.DevicePolicyEvaluationResult;
import org.wso2.carbon.identity.device.policy.api.service.DevicePolicyEvaluator;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.organization.management.service.internal.OrganizationManagementDataHolder;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

/**
 * Test class for DevicePolicyComplianceFunctionImpl.
 */
@WithCarbonHome
@WithH2Database(files = "dbscripts/h2.sql")
@WithRealmService(injectToSingletons = {IdentityTenantUtil.class, FrameworkServiceDataHolder.class,
        OrganizationManagementDataHolder.class},
        injectUMDataSourceTo = OrganizationManagementDataHolder.class)
public class DevicePolicyComplianceFunctionImplTest extends JsSequenceHandlerAbstractTest {

    private static final String POLICY_NAME = "test-device-policy";
    private static final String TENANT_DOMAIN = "test_domain";
    private static final String APP_RESOURCE_ID = "test-app-resource-id";
    private static final String TEST_USER = "test_user";
    private static final String COMPLIANT = "COMPLIANT";
    private static final String DEVICE_DATA_MISSING =
            POLICY_NAME + ":device token is missing or validation failed";

    @Mock
    private DevicePolicyEvaluator devicePolicyEvaluator;

    @BeforeClass
    @Parameters({"scriptEngine"})
    public void setUp(String scriptEngine) throws Exception {

        super.setUp(scriptEngine);
        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = true;
        sequenceHandlerRunner.registerJsFunction("isDevicePolicyCompliant",
                new DevicePolicyComplianceFunctionImpl());

        initMocks(this);
        DevicePolicyFunctionsServiceHolder.getInstance().setDevicePolicyEvaluator(devicePolicyEvaluator);
        IdentityEventService identityEventService = mock(IdentityEventService.class);
        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(identityEventService);
    }

    @BeforeMethod
    public void resetEvaluator() {

        reset(devicePolicyEvaluator);
    }

    @AfterClass
    protected void tearDown() {

        DevicePolicyFunctionsServiceHolder.getInstance().setDevicePolicyEvaluator(null);
        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(null);
    }

    @DataProvider(name = "evaluationResultProvider")
    public Object[][] evaluationResultProvider() {

        return new Object[][]{
                // A compliant device yields no reason, which the script maps to "COMPLIANT".
                {DevicePolicyEvaluationResult.compliant(POLICY_NAME), COMPLIANT},
                // A non compliant device yields the comma separated list of failed fields.
                {DevicePolicyEvaluationResult.nonCompliant(POLICY_NAME,
                        Collections.singletonList("isRooted")), "isRooted"},
                {DevicePolicyEvaluationResult.nonCompliant(POLICY_NAME,
                        Arrays.asList("isRooted", "osVersion")), "isRooted, osVersion"},
                // Incomplete device data yields the comma separated list of missing fields.
                {DevicePolicyEvaluationResult.incompleteDeviceData(POLICY_NAME,
                        Collections.singletonList("osVersion")), "osVersion"},
                {DevicePolicyEvaluationResult.incompleteDeviceData(POLICY_NAME,
                        Arrays.asList("osVersion", "platform")), "osVersion, platform"},
                // A missing policy is reported against the policy name resolved by the evaluator.
                {DevicePolicyEvaluationResult.policyNotFound(POLICY_NAME), POLICY_NAME + ":policy_not_found"},
        };
    }

    @Test(dataProvider = "evaluationResultProvider")
    public void testIsCompliant(DevicePolicyEvaluationResult evaluationResult, String expectedAcr) throws Exception {

        when(devicePolicyEvaluator.evaluate(anyString(), anyMap(), any(), anyString())).thenReturn(evaluationResult);

        AuthenticationContext context = getAuthenticationContextForSP(POLICY_NAME, deviceData());
        handle(context);

        Assert.assertEquals(context.getSelectedAcr(), expectedAcr);
    }

    @DataProvider(name = "invalidDeviceDataProvider")
    public Object[][] invalidDeviceDataProvider() {

        return new Object[][]{
                // The device data resolver did not put anything on the context.
                {null},
                // The context carries something that is not a device data map.
                {"not-a-map"},
        };
    }

    @Test(dataProvider = "invalidDeviceDataProvider")
    public void testIsCompliantWithInvalidDeviceData(Object deviceData) throws Exception {

        AuthenticationContext context = getAuthenticationContextForSP(POLICY_NAME, deviceData);
        handle(context);

        Assert.assertEquals(context.getSelectedAcr(), DEVICE_DATA_MISSING);
        verifyNoInteractions(devicePolicyEvaluator);
    }

    @Test
    public void testIsCompliantWithEmptyDeviceData() throws Exception {

        when(devicePolicyEvaluator.evaluate(anyString(), anyMap(), any(), anyString()))
                .thenReturn(DevicePolicyEvaluationResult.incompleteDeviceData(POLICY_NAME,
                        Collections.singletonList("platform")));

        // An empty map is still a map, so evaluation is delegated rather than short circuited.
        AuthenticationContext context = getAuthenticationContextForSP(POLICY_NAME, new HashMap<String, Object>());
        handle(context);

        Assert.assertEquals(context.getSelectedAcr(), "platform");
    }

    @DataProvider(name = "evaluationFailureProvider")
    public Object[][] evaluationFailureProvider() {

        return new Object[][]{
                // Client side failures are reported as a policy error.
                {new DevicePolicyClientException("Invalid policy.", "Invalid policy.", "DP-60001"),
                        POLICY_NAME + ":policy_error"},
                // Any other device policy failure is reported as an evaluation error.
                {new DevicePolicyServerException("Policy evaluation failed."),
                        POLICY_NAME + ":evaluation_error"},
        };
    }

    @Test(dataProvider = "evaluationFailureProvider")
    public void testIsCompliantWithEvaluationFailure(Exception exception, String expectedAcr) throws Exception {

        when(devicePolicyEvaluator.evaluate(anyString(), anyMap(), any(), anyString())).thenThrow(exception);

        AuthenticationContext context = getAuthenticationContextForSP(POLICY_NAME, deviceData());
        handle(context);

        Assert.assertEquals(context.getSelectedAcr(), expectedAcr);
    }

    @Test
    public void testEvaluatorInvokedWithContextValues() throws Exception {

        when(devicePolicyEvaluator.evaluate(anyString(), anyMap(), any(), anyString()))
                .thenReturn(DevicePolicyEvaluationResult.compliant(POLICY_NAME));

        Map<String, Object> deviceData = deviceData();
        AuthenticationContext context = getAuthenticationContextForSP(POLICY_NAME, deviceData);
        handle(context);

        ArgumentCaptor<Map<String, Object>> deviceDataCaptor = ArgumentCaptor.forClass(Map.class);
        verify(devicePolicyEvaluator).evaluate(eq(POLICY_NAME), deviceDataCaptor.capture(), eq(APP_RESOURCE_ID),
                eq(TENANT_DOMAIN));

        Map<String, Object> capturedDeviceData = deviceDataCaptor.getValue();
        Assert.assertEquals(capturedDeviceData, deviceData);
        // The evaluator mutates the device data it receives, so the context copy must not be handed over as is.
        Assert.assertNotSame(capturedDeviceData, deviceData);
    }

    private Map<String, Object> deviceData() {

        Map<String, Object> deviceData = new HashMap<>();
        deviceData.put("platform", "android");
        deviceData.put("osVersion", "14");
        deviceData.put("isRooted", false);
        return deviceData;
    }

    private void handle(AuthenticationContext context) throws JsTestException {

        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();
        sequenceHandlerRunner.handle(req, resp, context, TENANT_DOMAIN);
    }

    private AuthenticationContext getAuthenticationContextForSP(String policyName, Object deviceData)
            throws JsTestException {

        sequenceHandlerRunner.addSubjectAuthenticator("BasicMockAuthenticator", TEST_USER, Collections.emptyMap());
        ServiceProvider sp = sequenceHandlerRunner.loadServiceProviderFromResource(
                "device-policy-compliance-sp.xml", this);

        LocalAndOutboundAuthenticationConfig authConfig = sp.getLocalAndOutBoundAuthenticationConfig();
        AuthenticationScriptConfig scriptConfig = authConfig.getAuthenticationScriptConfig();
        scriptConfig.setContent(String.format(scriptConfig.getContent(), policyName));
        authConfig.setAuthenticationScriptConfig(scriptConfig);
        sp.setLocalAndOutBoundAuthenticationConfig(authConfig);

        AuthenticationContext context = sequenceHandlerRunner.createAuthenticationContext(sp);
        SequenceConfig sequenceConfig = sequenceHandlerRunner.getSequenceConfig(context, sp);
        context.setSequenceConfig(sequenceConfig);
        context.setServiceProviderResourceId(APP_RESOURCE_ID);
        if (deviceData != null) {
            context.setProperty(FrameworkConstants.DEVICE_DATA, deviceData);
        }
        context.initializeAnalyticsData();

        return context;
    }
}
