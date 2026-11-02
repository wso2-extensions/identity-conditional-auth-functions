/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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
 */

package org.wso2.carbon.identity.conditional.auth.functions.common.utils;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link AdaptiveAuthUtils}.
 */
@WithCarbonHome
public class AdaptiveAuthUtilsTest {

    /**
     * Data provider for {@link #testIsSaasApp}.
     *
     * Columns: context, expected
     */
    @DataProvider(name = "isSaasAppDataProvider")
    public Object[][] isSaasAppDataProvider() {

        // Null context → false.
        // Context with no SequenceConfig → false.
        AuthenticationContext ctxNoSeq = new AuthenticationContext();

        // SequenceConfig that returns null ApplicationConfig → false.
        SequenceConfig seqNullApp = mock(SequenceConfig.class);
        when(seqNullApp.getApplicationConfig()).thenReturn(null);
        AuthenticationContext ctxNullApp = new AuthenticationContext();
        ctxNullApp.setSequenceConfig(seqNullApp);

        // ApplicationConfig that returns null ServiceProvider → false.
        ApplicationConfig appNullSP = mock(ApplicationConfig.class);
        when(appNullSP.getServiceProvider()).thenReturn(null);
        SequenceConfig seqNullSP = mock(SequenceConfig.class);
        when(seqNullSP.getApplicationConfig()).thenReturn(appNullSP);
        AuthenticationContext ctxNullSP = new AuthenticationContext();
        ctxNullSP.setSequenceConfig(seqNullSP);

        return new Object[][]{
                // Null context → false.
                {null,                             false},
                // No SequenceConfig → false.
                {ctxNoSeq,                         false},
                // Null ApplicationConfig → false.
                {ctxNullApp,                       false},
                // Null ServiceProvider → false.
                {ctxNullSP,                        false},
                // Non-SaaS application → false.
                {buildContext("tenant.com", false), false},
                // SaaS application → true.
                {buildContext("tenant.com", true),  true},
        };
    }

    @Test(dataProvider = "isSaasAppDataProvider")
    public void testIsSaasApp(AuthenticationContext context, boolean expected) {

        Assert.assertEquals(AdaptiveAuthUtils.isSaasApp(context), expected);
    }

    /**
     * Data provider for {@link #testIsSaaSCrossTenantOperationsEnabled}.
     *
     * Columns: propertyValue, expected
     */
    @DataProvider(name = "isSaaSCrossTenantOperationsEnabledDataProvider")
    public Object[][] isSaaSCrossTenantOperationsEnabledDataProvider() {

        return new Object[][]{
                // Property absent (null) → defaults to false.
                {null,    false},
                // Property explicitly set to false → false.
                {"false", false},
                // Property explicitly set to true → true.
                {"true",  true},
        };
    }

    @Test(dataProvider = "isSaaSCrossTenantOperationsEnabledDataProvider")
    public void testIsSaaSCrossTenantOperationsEnabled(String propertyValue, boolean expected) {

        try (MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {
            identityUtil.when(() -> IdentityUtil.getProperty(Constants.SAAS_ENABLE_CROSS_TENANT_OPERATIONS))
                    .thenReturn(propertyValue);
            Assert.assertEquals(AdaptiveAuthUtils.isSaaSCrossTenantOperationsEnabled(), expected);
        }
    }

    /**
     * Data provider for {@link #testIsUserInCurrentTenant}.
     *
     * Columns: isSaas, isCrossTenantEnabled, isTenantQualifiedUrl,
     *          userTenantDomain, contextTenantDomain, carbonContextTenantDomain, expected
     */
    @DataProvider(name = "isUserInCurrentTenantDataProvider")
    public Object[][] isUserInCurrentTenantDataProvider() {

        return new Object[][]{
                // SaaS + cross-tenant enabled → bypass all domain checks, always true.
                {true,  true,  false, "t1.com", "t2.com", "carbon.super", true},
                {true,  true,  true,  "t1.com", "t2.com", "carbon.super", true},
                // SaaS + cross-tenant disabled, tenant-qualified=true → compare against PrivilegedCarbonContext.
                {true,  false, true,  "t1.com", "t2.com", "t1.com",       true},
                {true,  false, true,  "t1.com", "t2.com", "t2.com",       false},
                // Non-SaaS, tenant-qualified=true → compare against PrivilegedCarbonContext.
                {false, false, true,  "t1.com", "t2.com", "t1.com",       true},
                {false, false, true,  "t1.com", "t2.com", "t2.com",       false},
                // Non-SaaS, tenant-qualified=false → compare against context tenant domain.
                {false, false, false, "t1.com", "t1.com", "carbon.super", true},
                {false, false, false, "t1.com", "t2.com", "carbon.super", false},
        };
    }

    @Test(dataProvider = "isUserInCurrentTenantDataProvider")
    public void testIsUserInCurrentTenant(boolean isSaas, boolean isCrossTenantEnabled,
            boolean isTenantQualifiedUrl, String userTenantDomain, String contextTenantDomain,
            String carbonContextTenantDomain, boolean expected) {

        AuthenticationContext context = buildContext(contextTenantDomain, isSaas);

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

            identityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled)
                    .thenReturn(isTenantQualifiedUrl);
            identityUtil.when(() -> IdentityUtil.getProperty(Constants.SAAS_ENABLE_CROSS_TENANT_OPERATIONS))
                    .thenReturn(String.valueOf(isCrossTenantEnabled));

            PrivilegedCarbonContext.startTenantFlow();
            try {
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(carbonContextTenantDomain, false);
                Assert.assertEquals(AdaptiveAuthUtils.isUserInCurrentTenant(userTenantDomain, context), expected);
            } finally {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }
    }

    @Test
    public void testIsUserInCurrentTenantWithNullContext() {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

            identityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(false);
            identityUtil.when(() -> IdentityUtil.getProperty(Constants.SAAS_ENABLE_CROSS_TENANT_OPERATIONS))
                    .thenReturn("false");

            Assert.assertFalse(AdaptiveAuthUtils.isUserInCurrentTenant("t1.com", null));
        }
    }

    @Test
    public void testIsUserInCurrentTenantWithBlankContextTenantDomain() {

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain("");

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

            identityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(false);
            identityUtil.when(() -> IdentityUtil.getProperty(Constants.SAAS_ENABLE_CROSS_TENANT_OPERATIONS))
                    .thenReturn("false");

            Assert.assertFalse(AdaptiveAuthUtils.isUserInCurrentTenant("t1.com", context));
        }
    }

    private AuthenticationContext buildContext(String tenantDomain, boolean isSaasApp) {

        ServiceProvider serviceProvider = mock(ServiceProvider.class);
        when(serviceProvider.isSaasApp()).thenReturn(isSaasApp);

        ApplicationConfig appConfig = mock(ApplicationConfig.class);
        when(appConfig.getServiceProvider()).thenReturn(serviceProvider);

        SequenceConfig sequenceConfig = mock(SequenceConfig.class);
        when(sequenceConfig.getApplicationConfig()).thenReturn(appConfig);

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(tenantDomain);
        context.setSequenceConfig(sequenceConfig);
        return context;
    }
}
