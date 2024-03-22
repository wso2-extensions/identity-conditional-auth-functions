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

import org.mockito.Matchers;
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.conditional.auth.functions.notification.internal.NotificationFunctionServiceHolder;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsSequenceHandlerAbstractTest;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsTestException;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.services.IdentityEventService;

import java.lang.ref.Reference;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.testng.Assert.*;

/**
 * Test for sentMail in javascript
 */
@WithCarbonHome
@WithH2Database(files = "dbscripts/h2.sql")
@WithRealmService(injectToSingletons = FrameworkServiceDataHolder.class)
public class SendEmailFunctionImplTest extends JsSequenceHandlerAbstractTest {


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
            Event event = invocationOnMock.getArgumentAt(0, Event.class);
            System.out.println("Event " + event.getEventName());
            if(shouldThrowException) {
                throw new IdentityEventException("Mock throws shouldThrowException");
            }
            if (sendSuccessfully) {
                hasEmailSent.set(true);
            }
            return null;
        }).when(mockIdentityEventService).handleEvent(Matchers.any(Event.class));

        NotificationFunctionServiceHolder.getInstance().setIdentityEventService(mockIdentityEventService);
        ServiceProvider sp1 = sequenceHandlerRunner.loadServiceProviderFromResource("sendEmail-test-sp.xml", this);

        AuthenticationContext context = sequenceHandlerRunner.createAuthenticationContext(sp1);

        SequenceConfig sequenceConfig = sequenceHandlerRunner
                .getSequenceConfig(context, sp1);
        context.setSequenceConfig(sequenceConfig);
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

}