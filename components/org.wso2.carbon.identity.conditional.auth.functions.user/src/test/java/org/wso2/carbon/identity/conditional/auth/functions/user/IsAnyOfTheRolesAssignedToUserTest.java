/*
 * Copyright (c) 2025-2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.conditional.auth.functions.user;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.graaljs.JsGraalAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.util.Arrays;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Test class for IsAnyOfTheRolesAssignedToUserFunctionImpl.
 */
@WithCarbonHome
public class IsAnyOfTheRolesAssignedToUserTest {

    @BeforeClass
    public void setUp() {

        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super", true);
    }

    @AfterClass
    public void tearDown() {

        PrivilegedCarbonContext.destroyCurrentContext();
    }

    /**
     * Data provider for cross-tenant role-assignment check scenarios.
     *
     * Columns: isSaas, isCrossTenantEnabled, isTenantQualified,
     *          userTenantDomain, authContextTenantDomain, carbonContextTenantDomain, expected
     */
    @DataProvider(name = "crossTenantScenarioDataProvider")
    public Object[][] getCrossTenantScenarioData() {

        return new Object[][]{
                // Non-SaaS, tenant-qualified=false: validated against authCtx tenant.
                {false, false, false, "t2.com", "t2.com", "carbon.super", false},
                {false, false, false, "t1.com", "t2.com", "carbon.super", false},
                // Non-SaaS, tenant-qualified=true: validated against PCC tenant.
                {false, false, true,  "t2.com", "t3.com", "t2.com", false},
                {false, false, true,  "t1.com", "t3.com", "t2.com", false},
                // SaaS + cross-tenant enabled: bypass tenant check.
                {true,  true,  false, "t2.com", "t1.com", "carbon.super", false},
                {true,  true,  false, "t1.com", "t1.com", "carbon.super", false},
                // SaaS + cross-tenant disabled: falls through to normal check.
                {true,  false, false, "t2.com", "t1.com", "carbon.super", false},
        };
    }

    /**
     * Verifies cross-tenant behaviour of {@link IsAnyOfTheRolesAssignedToUserFunctionImpl#IsAnyOfTheRolesAssignedToUser}
     * across non-SaaS and SaaS scenarios, including the SaaS.EnableCrossTenantOperations config check.
     */
    @Test(dataProvider = "crossTenantScenarioDataProvider")
    public void testCrossTenantScenarioInSaaSApp(boolean isSaas, boolean isCrossTenantEnabled,
            boolean isTenantQualified, String userTenantDomain, String authContextTenantDomain,
            String carbonContextTenantDomain, boolean expected) throws Exception {

        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(carbonContextTenantDomain, true);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("testUser");
        authenticatedUser.setTenantDomain(userTenantDomain);
        authenticatedUser.setUserStoreDomain("PRIMARY");

        // Wire up SequenceConfig -> ApplicationConfig -> ServiceProvider chain.
        ServiceProvider serviceProvider = mock(ServiceProvider.class);
        when(serviceProvider.isSaasApp()).thenReturn(isSaas);

        ApplicationConfig appConfig = mock(ApplicationConfig.class);
        when(appConfig.getServiceProvider()).thenReturn(serviceProvider);

        SequenceConfig sequenceConfig = mock(SequenceConfig.class);
        when(sequenceConfig.getApplicationConfig()).thenReturn(appConfig);

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(authContextTenantDomain);
        context.setSequenceConfig(sequenceConfig);

        JsAuthenticatedUser jsUser = new JsGraalAuthenticatedUser(context, authenticatedUser);
        List<String> roles = Arrays.asList("role1", "role2");

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

            identityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(isTenantQualified);
            identityUtil.when(() -> IdentityUtil.getProperty(Constants.SAAS_ENABLE_CROSS_TENANT_OPERATIONS))
                    .thenReturn(String.valueOf(isCrossTenantEnabled));

            IsAnyOfTheRolesAssignedToUserFunctionImpl isAnyOfTheRolesAssignedToUserFunction =
                    new IsAnyOfTheRolesAssignedToUserFunctionImpl();
            boolean result = isAnyOfTheRolesAssignedToUserFunction.IsAnyOfTheRolesAssignedToUser(jsUser, roles);
            Assert.assertEquals(result, expected, "Cross-tenant role-assignment check should return " + expected);
        }
    }
}
