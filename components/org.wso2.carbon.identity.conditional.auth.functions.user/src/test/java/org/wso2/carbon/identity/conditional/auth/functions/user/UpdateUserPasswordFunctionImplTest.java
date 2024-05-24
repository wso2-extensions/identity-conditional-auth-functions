/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
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
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsSequenceHandlerAbstractTest;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsTestException;
import org.wso2.carbon.identity.conditional.auth.functions.user.internal.UserFunctionsServiceHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

@WithCarbonHome
@WithRealmService(injectToSingletons = {UserFunctionsServiceHolder.class, IdentityTenantUtil.class,
        FrameworkServiceDataHolder.class})
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

        sequenceHandlerRunner.addSubjectAuthenticator("BasicMockAuthenticator", "test_user", Collections.emptyMap());
        ServiceProvider sp = sequenceHandlerRunner.loadServiceProviderFromResource(spFileName, this);
        AuthenticationContext context = sequenceHandlerRunner.createAuthenticationContext(sp);
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
                {null, "newPassword", null, "User is not defined."},
                {jsAuthenticatedUser, null, null, "Password is not defined."},
                {jsAuthenticatedUser, "", null, "The provided password is empty."},
                {jsAuthenticatedUser, "newPassword", Collections.EMPTY_LIST, "Invalid argument type. " +
                        "Expected eventHandlers (Map<String, Object>)."}
        };
    }

    @Test(dataProvider = "updateUserPasswordWithEmptyInputDataProvider")
    public void testUpdateUserPasswordWithEmptyInput(JsAuthenticatedUser user, String password,
                                                     List<Object> eventHandlers, String errorMessage)
            throws UserStoreException {

        try {
            if (password == null) {
                testFunction.updateUserPassword(user);
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
}
