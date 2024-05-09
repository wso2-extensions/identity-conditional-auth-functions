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

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.openjdk.nashorn.JsOpenJdkNashornAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.central.log.mgt.internal.CentralLogMgtServiceComponentHolder;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants;
import org.wso2.carbon.identity.conditional.auth.functions.user.internal.UserFunctionsServiceHolder;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.DiagnosticLog;

import java.lang.reflect.Field;
import java.util.List;

import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

@WithCarbonHome
@WithRealmService(injectToSingletons = {FrameworkServiceDataHolder.class})
public class UpdateUserPasswordFunctionImplTest {

    private UpdateUserPasswordFunctionImpl testFunction;
    private JsAuthenticatedUser jsAuthenticatedUser;

    @Mock
    RealmService realmServiceMock;
    @Mock
    UserRealm userRealmMock;

    UserStoreManager userStoreManagerMock;
    IdentityEventService identityEventServiceMock;

    private final String USERNAME = "testUser";
    private final String PASSWORD = "password";
    private final String PASSWORD_UPDATE_STATUS_CLAIM = "http://wso2.org/claims/password_migration_status";

    @BeforeClass
    public void setUp() throws NoSuchFieldException, IllegalAccessException {

        testFunction = new UpdateUserPasswordFunctionImpl();
        initMocks(this);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(USERNAME);
        authenticatedUser.setTenantDomain("carbon.super");
        authenticatedUser.setUserStoreDomain("PRIMARY");
        authenticatedUser.setUserId("123456");
        jsAuthenticatedUser = new JsOpenJdkNashornAuthenticatedUser(authenticatedUser);

        // Diagnostic log related mocks.
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
    public void setUpMethod() throws org.wso2.carbon.user.api.UserStoreException, NoSuchFieldException,
            IllegalAccessException {

        Field userFunctionsServiceHolder = UserFunctionsServiceHolder.class.getDeclaredField("instance");
        userFunctionsServiceHolder.setAccessible(true);
        UserFunctionsServiceHolder instance = (UserFunctionsServiceHolder) userFunctionsServiceHolder.get(null);
        instance.setRealmService(realmServiceMock);

        userStoreManagerMock = mock(UserStoreManager.class);
        when(realmServiceMock.getTenantUserRealm(anyInt())).thenReturn(userRealmMock);
        when(userRealmMock.getUserStoreManager()).thenReturn(userStoreManagerMock);
        when(userStoreManagerMock.getSecondaryUserStoreManager(anyString())).thenReturn(userStoreManagerMock);

        // Diagnostic log related mocks.
        identityEventServiceMock = mock(IdentityEventService.class);
        Field logMgtServiceHolder = CentralLogMgtServiceComponentHolder.class.getDeclaredField(
                "centralLogMgtServiceComponentHolder");
        logMgtServiceHolder.setAccessible(true);
        CentralLogMgtServiceComponentHolder logMgtInstance =
                (CentralLogMgtServiceComponentHolder) logMgtServiceHolder.get(null);
        logMgtInstance.setIdentityEventService(identityEventServiceMock);
    }

    @DataProvider(name = "updateUserPasswordWithEmptyInputDataProvider")
    public Object[][] updateUserPasswordWithEmptyInputDataProvider() {

        return new Object[][]{
                {null, "newPassword", null, "User is not defined."},
                {jsAuthenticatedUser, null, null, "Password parameters are not defined."},
                {jsAuthenticatedUser, "", null, "The provided password is empty."},
                {jsAuthenticatedUser, "", "testClaim", "The provided password is empty."}
        };
    }

    @Test(dataProvider = "updateUserPasswordWithEmptyInputDataProvider")
    public void testUpdateUserPasswordWithEmptyInput(JsAuthenticatedUser user, String password,
                                                     String claimURI, String logMessage)
            throws UserStoreException, IdentityEventException {

        if (password == null && claimURI == null) {
            testFunction.updateUserPassword(user);
        } else {
            testFunction.updateUserPassword(user, password, claimURI);
        }

        // Assert that user store manager methods are never invoked.
        verify(userStoreManagerMock, times(0)).updateCredentialByAdmin(anyString(), anyString());

        // Assert for the correct diagnostic logs.
        ArgumentCaptor<Event> logEventCaptor = ArgumentCaptor.forClass(Event.class);
        verify(identityEventServiceMock).handleEvent(logEventCaptor.capture());
        assertDiagnosticLog(logEventCaptor.getValue(), Constants.LogConstants.ActionIDs.VALIDATE_INPUT_PARAMS,
                DiagnosticLog.ResultStatus.FAILED, logMessage);
    }

    @DataProvider(name = "updateUserPasswordDataProvider")
    public Object[][] updateUserPasswordDataProvider() {

        return new Object[][]{
                {null, null},
                {PASSWORD_UPDATE_STATUS_CLAIM, null},
                {PASSWORD_UPDATE_STATUS_CLAIM, "false"},
                {PASSWORD_UPDATE_STATUS_CLAIM, "true"}
        };
    }

    @Test(dataProvider = "updateUserPasswordDataProvider")
    public void testUpdateUserPassword(String claim, String claimValue)
            throws UserStoreException, IdentityEventException {

        if (claim != null) {
            when(userStoreManagerMock.getUserClaimValue(USERNAME, PASSWORD_UPDATE_STATUS_CLAIM, null))
                    .thenReturn(claimValue);
            testFunction.updateUserPassword(jsAuthenticatedUser, PASSWORD, PASSWORD_UPDATE_STATUS_CLAIM);

            if ("true".equals(claimValue)) {
                // Assert that user store manager methods are never invoked when the password is already updated.
                verify(userStoreManagerMock, times(0)).updateCredentialByAdmin(USERNAME, PASSWORD);

                // Assert for the correct diagnostic logs.
                ArgumentCaptor<Event> logEventCaptor = ArgumentCaptor.forClass(Event.class);
                verify(identityEventServiceMock).handleEvent(logEventCaptor.capture());
                assertDiagnosticLog(logEventCaptor.getValue(),
                        Constants.LogConstants.ActionIDs.UPDATE_USER_PASSWORD, DiagnosticLog.ResultStatus.FAILED,
                        "Password migration has already been completed for the user.");
            } else {
                // Assert that user store manager methods are invoked when the password is not updated.
                verify(userStoreManagerMock, times(1)).updateCredentialByAdmin(USERNAME, PASSWORD);
                verify(userStoreManagerMock, times(1))
                        .getUserClaimValue(USERNAME, PASSWORD_UPDATE_STATUS_CLAIM, null);
                verify(userStoreManagerMock, times(1))
                        .setUserClaimValue(USERNAME, PASSWORD_UPDATE_STATUS_CLAIM, "true", null);

                // Assert for the correct diagnostic logs.
                ArgumentCaptor<Event> logEventCaptor = ArgumentCaptor.forClass(Event.class);
                verify(identityEventServiceMock, times(2)).handleEvent(logEventCaptor.capture());
                List<Event> eventList = logEventCaptor.getAllValues();

                assertDiagnosticLog(eventList.get(0), Constants.LogConstants.ActionIDs.UPDATE_USER_PASSWORD,
                        DiagnosticLog.ResultStatus.SUCCESS, "User password updated successfully.");

                assertDiagnosticLog(eventList.get(1),
                        Constants.LogConstants.ActionIDs.UPDATE_USER_PASSWORD, DiagnosticLog.ResultStatus.SUCCESS,
                        "Password migration status claim updated successfully.");
            }
        } else {
            testFunction.updateUserPassword(jsAuthenticatedUser, PASSWORD);

            // Assert that only the updateCredentialByAdmin method is invoked.
            verify(userStoreManagerMock, times(1)).updateCredentialByAdmin(USERNAME, PASSWORD);
            verify(userStoreManagerMock, times(0))
                    .setUserClaimValue(USERNAME, PASSWORD_UPDATE_STATUS_CLAIM, "true", null);

            // Assert for the correct diagnostic logs.
            ArgumentCaptor<Event> logEventCaptor = ArgumentCaptor.forClass(Event.class);
            verify(identityEventServiceMock).handleEvent(logEventCaptor.capture());
            assertDiagnosticLog(logEventCaptor.getValue(), Constants.LogConstants.ActionIDs.UPDATE_USER_PASSWORD,
                    DiagnosticLog.ResultStatus.SUCCESS, "User password updated successfully.");
        }
    }

    private void assertDiagnosticLog(Event capturedEvent, String expectedActionID,
                                     DiagnosticLog.ResultStatus expectedResultStatus, String expectedMessage) {

        DiagnosticLog diagnosticLog = (DiagnosticLog) capturedEvent.getEventProperties().get("diagnosticLog");
        Assert.assertEquals(diagnosticLog.getComponentId(), Constants.LogConstants.ADAPTIVE_AUTH_SERVICE);
        Assert.assertEquals(diagnosticLog.getActionId(), expectedActionID);
        Assert.assertEquals(diagnosticLog.getResultStatus(), expectedResultStatus.name());
        Assert.assertEquals(diagnosticLog.getResultMessage(), expectedMessage);
    }
}
