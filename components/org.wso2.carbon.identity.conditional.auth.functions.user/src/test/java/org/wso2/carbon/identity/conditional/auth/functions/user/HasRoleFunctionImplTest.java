/*
 * Copyright (c) 2018-2026, WSO2 LLC. (http://www.wso2.com).
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

import org.testng.Assert;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.graaljs.JsGraalAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.central.log.mgt.internal.CentralLogMgtServiceComponentHolder;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsSequenceHandlerAbstractTest;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsTestException;
import org.wso2.carbon.identity.conditional.auth.functions.user.internal.UserFunctionsServiceHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.organization.management.service.internal.OrganizationManagementDataHolder;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Collections;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

@SuppressWarnings("deprecation")
@WithCarbonHome
@WithH2Database(files = "dbscripts/h2.sql")
@WithRealmService(injectToSingletons = {UserFunctionsServiceHolder.class, IdentityTenantUtil.class,
        FrameworkServiceDataHolder.class, OrganizationManagementDataHolder.class},
        injectUMDataSourceTo = OrganizationManagementDataHolder.class)
public class HasRoleFunctionImplTest extends JsSequenceHandlerAbstractTest {

    @WithRealmService
    private RealmService realmService;

    @BeforeClass
    public void setUpMocks() {

        IdentityEventService identityEventService = mock(IdentityEventService.class);
        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(identityEventService);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super", true);
    }

    @AfterClass
    public void tearDown() {

        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(null);
        PrivilegedCarbonContext.destroyCurrentContext();
    }

    @BeforeMethod
    protected void setUp() throws Exception {

        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = true;
        sequenceHandlerRunner.registerJsFunction("hasRole", new HasRoleFunctionImpl());
        UserRealm userRealm = realmService.getTenantUserRealm(-1234);
        userRealm.getUserStoreManager().addRole("admin", new String[]{"test_user1", "test_user2"}, null);
        userRealm.getUserStoreManager().addRole("manager", new String[]{"test_user1", "test_user3"}, null);
    }

    @Test(dataProvider = "hasRoleDataProvider")
    public void testHasRole(String user, boolean steppedUp) throws JsTestException, FrameworkException {

        sequenceHandlerRunner.addSubjectAuthenticator("BasicMockAuthenticator", user, Collections.emptyMap());

        ServiceProvider sp1 = sequenceHandlerRunner.loadServiceProviderFromResource("hasRole-test-sp.xml", this);

        AuthenticationContext context = sequenceHandlerRunner.createAuthenticationContext(sp1);
        context.setTenantDomain("carbon.super");

        SequenceConfig sequenceConfig = sequenceHandlerRunner
                .getSequenceConfig(context, sp1);
        context.setSequenceConfig(sequenceConfig);
        context.initializeAnalyticsData();

        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        sequenceHandlerRunner.handle(req, resp, context, "carbon.super");

        HttpServletRequest secondReq = sequenceHandlerRunner.createHttpServletRequest();
        secondReq.setAttribute("s", "S");
        HttpServletResponse secondResp = sequenceHandlerRunner.createHttpServletResponse();

        sequenceHandlerRunner.handle(req, resp, context, "carbon.super");
        assertNotNull(context.getSelectedAcr());
        assertEquals(Boolean.parseBoolean(context.getSelectedAcr()), steppedUp);
    }

    @DataProvider(name = "hasRoleDataProvider")
    public Object[][] getHasRoleData() {

        return new Object[][]{
                {"test_user1", true},
                {"test_user2", true},
                {"test_user3", false},
                {"test_user4", false},
        };
    }

    /**
     * Data provider for cross-tenant role check scenarios.
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
     * Verifies cross-tenant behaviour of {@link HasRoleFunctionImpl#hasRole} across non-SaaS
     * and SaaS scenarios, including the SaaS.EnableCrossTenantOperations config check.
     */
    @Test(dataProvider = "crossTenantScenarioDataProvider")
    public void testCrossTenantScenarioInSaaSApp(boolean isSaas, boolean isCrossTenantEnabled,
            boolean isTenantQualified, String userTenantDomain, String authContextTenantDomain,
            String carbonContextTenantDomain, boolean expected) throws Exception {

        PrivilegedCarbonContext.startTenantFlow();
        try {
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

            try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                    MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

                identityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(isTenantQualified);
                identityUtil.when(() -> IdentityUtil.getProperty(Constants.SAAS_ENABLE_CROSS_TENANT_OPERATIONS))
                        .thenReturn(String.valueOf(isCrossTenantEnabled));

                HasRoleFunctionImpl hasRoleFunction = new HasRoleFunctionImpl();
                boolean result = hasRoleFunction.hasRole(jsUser, "role1");
                Assert.assertEquals(result, expected, "Cross-tenant role check should return " + expected);
            }
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    /**
     * Verifies that the SaaS cross-tenant bypass allows the role check to reach the user store
     * and return {@code true} for a user who actually holds the queried role.
     * Without the bypass, a cross-tenant check short-circuits and returns {@code false} before
     * ever reaching the user store — so this confirms the bypass path is exercised end-to-end.
     */
    @Test
    public void testSaaSBypassAllowsCrossTenantRoleCheck() throws Exception {

        // SP is in "t1.com"; user belongs to "carbon.super" — a genuine cross-tenant scenario.
        PrivilegedCarbonContext.startTenantFlow();
        try {
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("t1.com", true);

            AuthenticatedUser authenticatedUser = new AuthenticatedUser();
            authenticatedUser.setUserName("test_user1"); // added to "admin" role in @BeforeMethod
            authenticatedUser.setTenantDomain("carbon.super");
            authenticatedUser.setUserStoreDomain("PRIMARY");

            ServiceProvider serviceProvider = mock(ServiceProvider.class);
            when(serviceProvider.isSaasApp()).thenReturn(true);

            ApplicationConfig appConfig = mock(ApplicationConfig.class);
            when(appConfig.getServiceProvider()).thenReturn(serviceProvider);

            SequenceConfig sequenceConfig = mock(SequenceConfig.class);
            when(sequenceConfig.getApplicationConfig()).thenReturn(appConfig);

            AuthenticationContext context = new AuthenticationContext();
            context.setTenantDomain("t1.com"); // SP tenant — different from user's tenant
            context.setSequenceConfig(sequenceConfig);

            JsAuthenticatedUser jsUser = new JsGraalAuthenticatedUser(context, authenticatedUser);

            try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
                    MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class)) {

                identityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(false);
                identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
                identityUtil.when(() -> IdentityUtil.getProperty(Constants.SAAS_ENABLE_CROSS_TENANT_OPERATIONS))
                        .thenReturn("true");

                HasRoleFunctionImpl hasRoleFunction = new HasRoleFunctionImpl();
                Assert.assertTrue(hasRoleFunction.hasRole(jsUser, "admin"),
                        "SaaS bypass should allow cross-tenant role check to reach the user store and return true");
            }
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }
}
