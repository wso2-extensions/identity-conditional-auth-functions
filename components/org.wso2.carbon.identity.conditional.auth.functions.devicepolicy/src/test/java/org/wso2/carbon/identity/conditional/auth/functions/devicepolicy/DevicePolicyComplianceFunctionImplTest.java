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
import org.wso2.carbon.identity.application.authentication.framework.handler.device.DeviceDataResolver;
import org.wso2.carbon.identity.application.authentication.framework.handler.device.ResolvedDeviceData;
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
import org.wso2.carbon.identity.device.policy.api.constant.DevicePolicyErrorMessage;
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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;
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
    private static final String USER_TENANT_DOMAIN = "carbon.super";
    private static final String COMPLIANT = "boolean|true|COMPLIANT|||";
    private static final String DEVICE_DATA_MISSING = errorResult(
            DevicePolicyComplianceFunctionImpl.ERROR_DEVICE_DATA_UNAVAILABLE);

    @Mock
    private DevicePolicyEvaluator devicePolicyEvaluator;

    @Mock
    private DeviceDataResolver deviceDataResolver;
    @BeforeClass
    @Parameters({"scriptEngine"})
    public void setUp(String scriptEngine) throws Exception {

        super.setUp(scriptEngine);
        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = true;
        sequenceHandlerRunner.registerJsFunction("evaluateDevicePolicy",
                new DevicePolicyComplianceFunctionImpl());

        initMocks(this);
        DevicePolicyFunctionsServiceHolder.getInstance().setDevicePolicyEvaluator(devicePolicyEvaluator);
        FrameworkServiceDataHolder.getInstance().setDeviceDataResolver(deviceDataResolver);
        IdentityEventService identityEventService = mock(IdentityEventService.class);
        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(identityEventService);
    }

    @BeforeMethod
    public void resetEvaluator() {

        reset(devicePolicyEvaluator, deviceDataResolver);
        when(deviceDataResolver.isValidDevice(anyString(), anyString(), anyString())).thenReturn(true);
    }

    @AfterClass
    protected void tearDown() {

        DevicePolicyFunctionsServiceHolder.getInstance().setDevicePolicyEvaluator(null);
        FrameworkServiceDataHolder.getInstance().setDeviceDataResolver(null);
        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(null);
    }

    @DataProvider(name = "evaluationResultProvider")
    public Object[][] evaluationResultProvider() {

        return new Object[][]{
                // A compliant device is reported as compliant with no failed or missing fields.
                {DevicePolicyEvaluationResult.compliant(POLICY_NAME), COMPLIANT},
                // A non compliant device exposes the failed fields as an array.
                {DevicePolicyEvaluationResult.nonCompliant(POLICY_NAME,
                        Collections.singletonList("isRooted")), "boolean|false|NON_COMPLIANT|isRooted||"},
                {DevicePolicyEvaluationResult.nonCompliant(POLICY_NAME,
                        Arrays.asList("isRooted", "osVersion")), "boolean|false|NON_COMPLIANT|isRooted,osVersion||"},
                // Incomplete device data exposes the missing fields as an array.
                {DevicePolicyEvaluationResult.incompleteDeviceData(POLICY_NAME,
                        Collections.singletonList("osVersion")), "boolean|false|INCOMPLETE_DEVICE_DATA||osVersion|"},
                {DevicePolicyEvaluationResult.incompleteDeviceData(POLICY_NAME,
                        Arrays.asList("osVersion", "platform")),
                        "boolean|false|INCOMPLETE_DEVICE_DATA||osVersion,platform|"},
        };
    }

    @Test(dataProvider = "evaluationResultProvider")
    public void testEvaluate(DevicePolicyEvaluationResult evaluationResult, String expectedAcr) throws Exception {

        when(devicePolicyEvaluator.evaluateByPolicyName(anyString(), anyMap(), any(), anyString())).thenReturn(evaluationResult);

        AuthenticationContext context = getAuthenticationContextForSP(POLICY_NAME, deviceData());
        handle(context);

        Assert.assertEquals(context.getSelectedAcr(), expectedAcr);
    }

    @DataProvider(name = "invalidDeviceDataProvider")
    public Object[][] invalidDeviceDataProvider() {

        return new Object[][]{
                // The device data resolver did not put anything on the context.
                {null},
                {"not-a-map"},
                // A raw map is not resolved device data.
                {Collections.singletonMap("platform", "android")},
        };
    }

    @Test(dataProvider = "invalidDeviceDataProvider")
    public void testEvaluateWithInvalidDeviceData(Object deviceData) throws Exception {

        AuthenticationContext context = getAuthenticationContextForSP(POLICY_NAME, deviceData);
        handle(context);

        Assert.assertEquals(context.getSelectedAcr(), DEVICE_DATA_MISSING);
        verifyNoInteractions(devicePolicyEvaluator);
    }

    @Test
    public void testEvaluateWithEmptyDeviceData() throws Exception {

        when(devicePolicyEvaluator.evaluateByPolicyName(anyString(), anyMap(), any(), anyString()))
                .thenReturn(DevicePolicyEvaluationResult.incompleteDeviceData(POLICY_NAME,
                        Collections.singletonList("platform")));

        AuthenticationContext context = getAuthenticationContextForSP(POLICY_NAME,
                boundDeviceData(new HashMap<>()));
        handle(context);

        Assert.assertEquals(context.getSelectedAcr(), "boolean|false|INCOMPLETE_DEVICE_DATA||platform|");
    }

    @DataProvider(name = "evaluationFailureProvider")
    public Object[][] evaluationFailureProvider() {

        return new Object[][]{
                // A missing policy is distinguished by its error code.
                {new DevicePolicyClientException("Device policy not found.", "Device policy not found.",
                        DevicePolicyErrorMessage.ERROR_DEVICE_POLICY_NOT_FOUND.getCode()),
                        errorResult(DevicePolicyComplianceFunctionImpl.ERROR_POLICY_NOT_FOUND)},
                // Any other client side failure is reported as a policy error.
                {new DevicePolicyClientException("Invalid policy.", "Invalid policy.", "DP-60001"),
                        errorResult(DevicePolicyComplianceFunctionImpl.ERROR_POLICY_ERROR)},
                // Any other device policy failure is reported as an evaluation error.
                {new DevicePolicyServerException("Policy evaluation failed."),
                        errorResult(DevicePolicyComplianceFunctionImpl.ERROR_EVALUATION_ERROR)},
        };
    }

    @Test(dataProvider = "evaluationFailureProvider")
    public void testEvaluateWithEvaluationFailure(Exception exception, String expectedAcr) throws Exception {

        when(devicePolicyEvaluator.evaluateByPolicyName(anyString(), anyMap(), any(), anyString())).thenThrow(exception);

        AuthenticationContext context = getAuthenticationContextForSP(POLICY_NAME, deviceData());
        handle(context);

        Assert.assertEquals(context.getSelectedAcr(), expectedAcr);
    }

    @Test
    public void testEvaluatorInvokedWithContextValues() throws Exception {

        when(devicePolicyEvaluator.evaluateByPolicyName(anyString(), anyMap(), any(), anyString()))
                .thenReturn(DevicePolicyEvaluationResult.compliant(POLICY_NAME));

        ResolvedDeviceData deviceData = deviceData();
        AuthenticationContext context = getAuthenticationContextForSP(POLICY_NAME, deviceData);
        handle(context);

        // The device data is read for the current user in the resident tenant of the user.
        ArgumentCaptor<String> userIdCaptor = ArgumentCaptor.forClass(String.class);
        verify(deviceData).getDeviceData(userIdCaptor.capture(), eq(USER_TENANT_DOMAIN));
        Assert.assertEquals(userIdCaptor.getValue(), context.getLastAuthenticatedUser().getUserId());
        verify(devicePolicyEvaluator).evaluateByPolicyName(eq(POLICY_NAME), eq(deviceClaims()),
                eq(APP_RESOURCE_ID), eq(TENANT_DOMAIN));
        verify(devicePolicyEvaluator, never()).evaluate(anyString(), anyMap(), any(), anyString());
    }

    @Test
    public void testEvaluateWhenDeviceDataIsNotAvailableForTheUser() throws Exception {

        // Another user, another tenant, an inactive device or no resolver.
        ResolvedDeviceData deviceData = mock(ResolvedDeviceData.class, withSettings().serializable());
        when(deviceData.getDeviceData(anyString(), anyString())).thenReturn(null);

        AuthenticationContext context = getAuthenticationContextForSP(POLICY_NAME, deviceData);
        handle(context);

        Assert.assertEquals(context.getSelectedAcr(), DEVICE_DATA_MISSING);
        verifyNoInteractions(devicePolicyEvaluator);
    }

    @Test
    public void testEvaluateWithDeviceOfAnotherUser() throws Exception {

        AuthenticationContext context = getAuthenticationContextForSP(POLICY_NAME,
                new ResolvedDeviceData("device-id", "another-user-id", USER_TENANT_DOMAIN, deviceClaims()));
        handle(context);

        Assert.assertEquals(context.getSelectedAcr(), DEVICE_DATA_MISSING);
        verifyNoInteractions(devicePolicyEvaluator);
        verify(deviceDataResolver, never()).isValidDevice(anyString(), anyString(), anyString());
    }

    @Test
    public void testEvaluateWithoutAuthenticatedUser() throws Exception {

        ResolvedDeviceData deviceData = deviceData();
        AuthenticationContext context = getAuthenticationContextForSP(
                "device-policy-compliance-before-login-sp.xml", POLICY_NAME, deviceData);
        handle(context);

        Assert.assertEquals(context.getSelectedAcr(), DEVICE_DATA_MISSING);
        verify(deviceData, never()).getDeviceData(any(), any());
        verifyNoInteractions(devicePolicyEvaluator);
    }

    private static String errorResult(String errorCode) {

        return "boolean|false|ERROR|||" + errorCode;
    }

    private Map<String, Object> deviceClaims() {

        Map<String, Object> deviceData = new HashMap<>();
        deviceData.put("platform", "android");
        deviceData.put("osVersion", "14");
        deviceData.put("isRooted", false);
        return deviceData;
    }

    private ResolvedDeviceData deviceData() {

        return boundDeviceData(deviceClaims());
    }

    /**
     * Device data that is available for any user, since the user ID of the mock authenticator is random.
     */
    private ResolvedDeviceData boundDeviceData(Map<String, Object> deviceData) {

        ResolvedDeviceData resolvedDeviceData = mock(ResolvedDeviceData.class, withSettings().serializable());
        when(resolvedDeviceData.getDeviceData(anyString(), anyString()))
                .thenReturn(Collections.unmodifiableMap(deviceData));
        return resolvedDeviceData;
    }

    private void handle(AuthenticationContext context) throws JsTestException {

        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();
        sequenceHandlerRunner.handle(req, resp, context, TENANT_DOMAIN);
    }

    private AuthenticationContext getAuthenticationContextForSP(String policyName, Object deviceData)
            throws JsTestException {

        return getAuthenticationContextForSP("device-policy-compliance-sp.xml", policyName, deviceData);
    }

    private AuthenticationContext getAuthenticationContextForSP(String spResource, String policyName,
                                                                Object deviceData) throws JsTestException {

        sequenceHandlerRunner.addSubjectAuthenticator("BasicMockAuthenticator", TEST_USER, Collections.emptyMap());
        ServiceProvider sp = sequenceHandlerRunner.loadServiceProviderFromResource(spResource, this);

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
