/*
 * Copyright (c) 2024-2026, WSO2 LLC. (http://www.wso2.com).
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
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.graaljs.JsGraalAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.openjdk.nashorn.JsOpenJdkNashornAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.dao.impl.CacheBackedLongWaitStatusDAO;
import org.wso2.carbon.identity.application.authentication.framework.dao.impl.LongWaitStatusDAOImpl;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.store.LongWaitStatusStoreService;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.central.log.mgt.internal.CentralLogMgtServiceComponentHolder;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.conditional.auth.functions.common.internal.FunctionsDataHolder;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsSequenceHandlerAbstractTest;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsTestException;
import org.wso2.carbon.identity.conditional.auth.functions.user.internal.UserFunctionsServiceHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.organization.management.service.internal.OrganizationManagementDataHolder;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

@WithCarbonHome
@WithRealmService(injectToSingletons = {UserFunctionsServiceHolder.class, IdentityTenantUtil.class,
        FrameworkServiceDataHolder.class, OrganizationManagementDataHolder.class},
        injectUMDataSourceTo = OrganizationManagementDataHolder.class)
@WithH2Database(files = "dbscripts/h2.sql")
public class UpdateUserPasswordFunctionImplTest extends JsSequenceHandlerAbstractTest {

    RealmService realmServiceMock;
    UserRealm userRealmMock;
    FunctionsDataHolder functionsDataHolderMock;
    UserStoreManager userStoreManagerMock;
    IdentityEventService identityEventServiceMock;

    private UpdateUserPasswordFunctionImpl testFunction;

    @BeforeClass
    @Parameters({"scriptEngine"})
    public void setUp(String scriptEngine) throws Exception {

        super.setUp(scriptEngine);
        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = true;
        sequenceHandlerRunner.registerJsFunction("updateUserPassword", new UpdateUserPasswordFunctionImpl());

        initMocks(this);
        testFunction = new UpdateUserPasswordFunctionImpl();

        functionsDataHolderMock = mock(FunctionsDataHolder.class);
        Field functionsDataHolderInstance = FunctionsDataHolder.class.getDeclaredField("instance");
        functionsDataHolderInstance.setAccessible(true);
        functionsDataHolderInstance.set(null, functionsDataHolderMock);

        Field frameworkServiceDataHolderInstance = FrameworkServiceDataHolder.class.getDeclaredField("instance");
        frameworkServiceDataHolderInstance.setAccessible(true);
        FrameworkServiceDataHolder availableInstance =
                (FrameworkServiceDataHolder) frameworkServiceDataHolderInstance.get(null);

        LongWaitStatusDAOImpl daoImpl = new LongWaitStatusDAOImpl();
        CacheBackedLongWaitStatusDAO cacheBackedDao = new CacheBackedLongWaitStatusDAO(daoImpl);
        int connectionTimeout = 10000;
        LongWaitStatusStoreService longWaitStatusStoreService =
                new LongWaitStatusStoreService(cacheBackedDao, connectionTimeout);
        availableInstance.setLongWaitStatusStoreService(longWaitStatusStoreService);

        // Set and initialize diagnostic log mode.
        Field serverConfiguration = ServerConfiguration.class.getDeclaredField("instance");
        serverConfiguration.setAccessible(true);
        ServerConfiguration serverConfigurationInstance = (ServerConfiguration) serverConfiguration.get(null);
        serverConfigurationInstance.setConfigurationProperty("DiagnosticLogMode", "full");
    }

    @AfterMethod
    public void tearDownMethod() {

        PrivilegedCarbonContext.destroyCurrentContext();
    }

    @AfterClass
    public void tearDown() throws NoSuchFieldException, IllegalAccessException {

        // Reset diagnostic log mode.
        Field serverConfiguration = ServerConfiguration.class.getDeclaredField("instance");
        serverConfiguration.setAccessible(true);
        ServerConfiguration serverConfigurationInstance = (ServerConfiguration) serverConfiguration.get(null);
        serverConfigurationInstance.setConfigurationProperty("DiagnosticLogMode", "");
    }

    @BeforeMethod
    public void setUpMethod() throws NoSuchFieldException, IllegalAccessException,
            org.wso2.carbon.user.api.UserStoreException {

        // Mock realm service and user store manager.
        realmServiceMock = mock(RealmService.class);
        userRealmMock = mock(UserRealm.class);
        userStoreManagerMock = mock(UserStoreManager.class);
        Field userFunctionsServiceHolder = UserFunctionsServiceHolder.class.getDeclaredField("instance");
        userFunctionsServiceHolder.setAccessible(true);
        UserFunctionsServiceHolder instance = (UserFunctionsServiceHolder) userFunctionsServiceHolder.get(null);
        instance.setRealmService(realmServiceMock);

        when(realmServiceMock.getTenantUserRealm(anyInt())).thenReturn(userRealmMock);
        when(userRealmMock.getUserStoreManager()).thenReturn(userStoreManagerMock);
        when(userStoreManagerMock.getSecondaryUserStoreManager(anyString())).thenReturn(userStoreManagerMock);

        // Mock identity event service for diagnostic log publishing.
        identityEventServiceMock = mock(IdentityEventService.class);
        Field logMgtServiceHolder = CentralLogMgtServiceComponentHolder.class.getDeclaredField(
                "centralLogMgtServiceComponentHolder");
        logMgtServiceHolder.setAccessible(true);
        CentralLogMgtServiceComponentHolder logMgtInstance =
                (CentralLogMgtServiceComponentHolder) logMgtServiceHolder.get(null);
        logMgtInstance.setIdentityEventService(identityEventServiceMock);
    }

    private AuthenticationContext getAuthenticationContextForSP(String spFileName) throws JsTestException {

        sequenceHandlerRunner.addSubjectAuthenticator("BasicMockAuthenticator",
                "test_user@test_domain", Collections.emptyMap());
        ServiceProvider sp = sequenceHandlerRunner.loadServiceProviderFromResource(spFileName, this);
        AuthenticationContext context = sequenceHandlerRunner.createAuthenticationContext(sp);
        context.setTenantDomain("test_domain");
        SequenceConfig sequenceConfig = sequenceHandlerRunner.getSequenceConfig(context, sp);
        context.setSequenceConfig(sequenceConfig);
        context.initializeAnalyticsData();

        return context;
    }

    @DataProvider(name = "updateUserPasswordWithEmptyInputDataProvider")
    public Object[][] updateUserPasswordWithEmptyInputDataProvider() {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("test_user");
        authenticatedUser.setTenantDomain("carbon.super");
        authenticatedUser.setUserStoreDomain("PRIMARY");
        authenticatedUser.setUserId("123456");
        JsAuthenticatedUser jsAuthenticatedUser = new JsOpenJdkNashornAuthenticatedUser(authenticatedUser);

        return new Object[][]{
                // user, newPassword, eventHandlers, skipPasswordValidation, expectedError
                {null, "newPassword", null, null, "User is not defined."},
                {jsAuthenticatedUser, null, null, null, "Password is not defined."},
                {jsAuthenticatedUser, "", null, null, "The provided password is empty."},
                {jsAuthenticatedUser, "newPassword", Collections.EMPTY_LIST, true, "Invalid argument type. " +
                        "Expected eventHandlers (Map<String, Object>)."}
        };
    }

    @Test(dataProvider = "updateUserPasswordWithEmptyInputDataProvider")
    public void testUpdateUserPasswordWithEmptyInput(JsAuthenticatedUser user, String password,
                                                     List<Object> eventHandlers, Boolean skipPasswordValidation,
                                                     String errorMessage)
            throws UserStoreException {

        try {
            if (password == null) {
                testFunction.updateUserPassword(user);
            } else if (eventHandlers != null && skipPasswordValidation != null) {
                testFunction.updateUserPassword(user, password, eventHandlers, skipPasswordValidation);
            } else if (eventHandlers != null) {
                testFunction.updateUserPassword(user, password, eventHandlers);
            } else {
                testFunction.updateUserPassword(user, password);
            }
        } catch (IllegalArgumentException e) {
            // Assert for the correct exception.
            Assert.assertEquals(e.getMessage(), errorMessage);
        }

        // Assert that user store manager methods are never invoked.
        verify(userStoreManagerMock, times(0)).updateCredentialByAdmin(anyString(), anyString());
    }

    @Test
    public void testUpdateUserPassword() throws UserStoreException, JsTestException {

        AuthenticationContext context = getAuthenticationContextForSP("update-password-sp.xml");
        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        sequenceHandlerRunner.handle(req, resp, context, "test_domain");

        // Assert that updateCredentialByAdmin method is invoked.
        verify(userStoreManagerMock, times(1)).updateCredentialByAdmin(anyString(), any());
    }

    @Test
    public void testUpdateUserPasswordWithCallbacks() throws UserStoreException, JsTestException {

        AuthenticationContext context = getAuthenticationContextForSP("update-password-async-sp.xml");
        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        sequenceHandlerRunner.handle(req, resp, context, "test_domain");

        // Assert that updateCredentialByAdmin method is invoked.
        verify(userStoreManagerMock, times(1)).updateCredentialByAdmin(anyString(), any());
    }

    /**
     * Data provider for cross-tenant password update scenarios.
     *
     * Columns: isSaas, isCrossTenantEnabled, isTenantQualified,
     *          userTenantDomain, authContextTenantDomain, carbonContextTenantDomain, shouldSucceed
     */
    @DataProvider(name = "crossTenantScenarioDataProvider")
    public Object[][] getCrossTenantScenarioData() {

        return new Object[][]{
                // Non-SaaS, tenant-qualified=false: validated against authCtx tenant.
                {false, false, false, "t2.com", "t2.com", "carbon.super", true},  // Same tenant - should succeed
                {false, false, false, "t1.com", "t2.com", "carbon.super", false}, // Cross-tenant - should fail
                // Non-SaaS, tenant-qualified=true: validated against PCC tenant.
                {false, false, true,  "t2.com", "t3.com", "t2.com", true},  // Same tenant - should succeed
                {false, false, true,  "t1.com", "t3.com", "t2.com", false}, // Cross-tenant - should fail
                // SaaS + cross-tenant enabled: bypass tenant check.
                {true,  true,  false, "t2.com", "t1.com", "carbon.super", true},  // SaaS bypass - should succeed
                {true,  true,  false, "t1.com", "t1.com", "carbon.super", true},  // SaaS bypass - should succeed
                // SaaS + cross-tenant disabled: falls through to normal check.
                {true,  false, false, "t2.com", "t1.com", "carbon.super", false}, // Cross-tenant - should fail
        };
    }

    /**
     * Verifies cross-tenant behaviour of {@link UpdateUserPasswordFunctionImpl#updateUserPassword} across
     * non-SaaS and SaaS scenarios, including the SaaS.EnableCrossTenantOperations config check.
     */
    @Test(dataProvider = "crossTenantScenarioDataProvider")
    public void testCrossTenantUpdatePasswordInSaaSApp(boolean isSaas, boolean isCrossTenantEnabled,
            boolean isTenantQualified, String userTenantDomain, String authContextTenantDomain,
            String carbonContextTenantDomain, boolean shouldSucceed) throws Exception {

        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(carbonContextTenantDomain, true);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("testUser");
        authenticatedUser.setTenantDomain(userTenantDomain);
        authenticatedUser.setUserStoreDomain("PRIMARY");
        authenticatedUser.setUserId("123456");

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

            // Call updateUserPassword (exceptions are caught internally and not re-thrown)
            testFunction.updateUserPassword(jsUser, "newPassword");
            
            // Verify whether updateCredentialByAdmin was called based on expected outcome
            if (shouldSucceed) {
                // For same-tenant or SaaS cross-tenant enabled scenarios, operation should succeed.
                verify(userStoreManagerMock, times(1)).updateCredentialByAdmin(anyString(), any());
            } else {
                // For cross-tenant operations without SaaS bypass, operation should be blocked.
                verify(userStoreManagerMock, times(0)).updateCredentialByAdmin(anyString(), any());
            }
        }
    }
}
