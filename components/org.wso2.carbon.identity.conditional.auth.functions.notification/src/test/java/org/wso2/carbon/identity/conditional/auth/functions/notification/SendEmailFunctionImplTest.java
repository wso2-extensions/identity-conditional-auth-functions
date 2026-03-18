/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.conditional.auth.functions.notification;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.graaljs.JsGraalAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.central.log.mgt.internal.CentralLogMgtServiceComponentHolder;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.conditional.auth.functions.notification.internal.NotificationFunctionServiceHolder;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsSequenceHandlerAbstractTest;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsTestException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.organization.management.service.internal.OrganizationManagementDataHolder;

import java.util.concurrent.atomic.AtomicBoolean;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertEquals;

/**
 * Test for sentMail in javascript
 */
@WithCarbonHome
@WithH2Database(files = "dbscripts/h2.sql")
@WithRealmService(injectToSingletons = {FrameworkServiceDataHolder.class, OrganizationManagementDataHolder.class},
        injectUMDataSourceTo = OrganizationManagementDataHolder.class)
public class SendEmailFunctionImplTest extends JsSequenceHandlerAbstractTest {

    @BeforeClass
    protected void setUpMocks() {

        IdentityEventService identityEventService = mock(IdentityEventService.class);
        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(identityEventService);
    }

    @AfterClass
    protected void tearDown() {

        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(null);
    }

    @BeforeMethod
    protected void setUp() throws Exception {

        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = true;
        sequenceHandlerRunner.registerJsFunction("sendEmail", new SendEmailFunctionImpl());
    }

    @Test(dataProvider = "emailEvents")
    public void testSendMail(boolean sendSuccessfully, boolean shouldThrowException) throws JsTestException, IdentityEventException {

        AtomicBoolean hasEmailSent = new AtomicBoolean(false);
        IdentityEventService mockIdentityEventService = Mockito.mock(IdentityEventService.class);
        Mockito.doAnswer(invocationOnMock -> {
            Event event = invocationOnMock.getArgument(0, Event.class);
            System.out.println("Event " + event.getEventName());
            if(shouldThrowException) {
                throw new IdentityEventException("Mock throws shouldThrowException");
            }
            if (sendSuccessfully) {
                hasEmailSent.set(true);
            }
            return null;
        }).when(mockIdentityEventService).handleEvent(any(Event.class));

        NotificationFunctionServiceHolder.getInstance().setIdentityEventService(mockIdentityEventService);
        ServiceProvider sp1 = sequenceHandlerRunner.loadServiceProviderFromResource("sendEmail-test-sp.xml", this);

        AuthenticationContext context = sequenceHandlerRunner.createAuthenticationContext(sp1);

        SequenceConfig sequenceConfig = sequenceHandlerRunner
                .getSequenceConfig(context, sp1);
        context.setSequenceConfig(sequenceConfig);
        context.setTenantDomain("carbon.super");
        context.initializeAnalyticsData();

        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        sequenceHandlerRunner.handle(req, resp, context, "carbon.super");

        assertEquals(hasEmailSent.get(), sendSuccessfully);
    }

    @DataProvider(name = "emailEvents")
    public Object[][] getEmailEvents() {
        return new Object[][]{
                {true, false},
                {false, true}

        };
    }

    @DataProvider(name = "isUserInCurrentTenantDataProvider")
    public Object[][] getIsUserInCurrentTenantData() {

        return new Object[][]{
                {true, "t2.com", "t1.com", "t2.com", false},
                {false, "t2.com", "t1.com", "carbon.super", false},
        };
    }

    @Test(dataProvider = "isUserInCurrentTenantDataProvider")
    public void testCrossTenantScenarioReturnsFalse(boolean isTenantQualified, String authContextTenantDomain,
            String userTenantDomain, String carbonContextTenantDomain, boolean expected) throws Exception {

        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(carbonContextTenantDomain, true);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("testUser");
        authenticatedUser.setTenantDomain(userTenantDomain);
        authenticatedUser.setUserStoreDomain("PRIMARY");

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(authContextTenantDomain);

        JsAuthenticatedUser jsUser = new JsGraalAuthenticatedUser(context, authenticatedUser);

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class)) {
            identityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(isTenantQualified);
            SendEmailFunctionImpl sendEmailFunction = new SendEmailFunctionImpl();
            boolean result = sendEmailFunction.sendMail(jsUser, "templateId", null);
            assertEquals(result, expected, "Cross-tenant send email check should return " + expected);
        }
    }
}
