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

package org.wso2.carbon.identity.conditional.auth.functions.http;

import org.apache.axiom.om.util.Base64;
import org.apache.commons.io.Charsets;
import org.json.simple.JSONObject;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.TransientObjectWrapper;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.conditional.auth.functions.http.util.HTTPConstants;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsSequenceHandlerAbstractTest;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsSequenceHandlerRunner;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsTestException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.verify;

/**
 * Test for setCookie and get cookie
 */
@WithCarbonHome
@WithH2Database(files = {"dbscripts/h2.sql"})
@WithRealmService(injectToSingletons = FrameworkServiceDataHolder.class)
public class CookieFunctionImplTest extends JsSequenceHandlerAbstractTest {

    @BeforeMethod
    @Parameters({"scriptEngine"})
    protected void setUp(String scriptEngine) throws Exception {

        super.setUp(scriptEngine);
        sequenceHandlerRunner.registerJsFunction("setCookie", (SetCookieFunction) new CookieFunctionImpl()::setCookie);
        sequenceHandlerRunner.registerJsFunction("getCookieValue", (GetCookieFunction) new CookieFunctionImpl()
                ::getCookieValue);
    }

    @Test
    public void testSetCookie() throws JsTestException {

        ServiceProvider sp1 = sequenceHandlerRunner.loadServiceProviderFromResource("set-cookie-test-sp.xml", this);

        AuthenticationContext context = sequenceHandlerRunner.createAuthenticationContext(sp1);

        SequenceConfig sequenceConfig = sequenceHandlerRunner.getSequenceConfig(context, sp1);
        context.setSequenceConfig(sequenceConfig);
        context.initializeAnalyticsData();

        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        context.addParameter(FrameworkConstants.RequestAttribute.HTTP_REQUEST, new TransientObjectWrapper(req));
        context.addParameter(FrameworkConstants.RequestAttribute.HTTP_RESPONSE, new TransientObjectWrapper(resp));

        sequenceHandlerRunner.handle(req, resp, context, "carbon.super");

        JSONObject cookieValueJson = new JSONObject();
        cookieValueJson.put(HTTPConstants.VALUE, "test");
        cookieValueJson.put(HTTPConstants.SIGNATURE, null);
        String cookieValue = cookieValueJson.toString();

        ArgumentCaptor<Cookie> argumentCaptor = ArgumentCaptor.forClass(Cookie.class);
        verify(resp).addCookie(argumentCaptor.capture());
        Assert.assertEquals(argumentCaptor.getValue().getValue(), Base64.encode(cookieValue.getBytes(Charsets.UTF_8)));
    }

    @Test
    public void testGetCookie() throws JsTestException {

        ServiceProvider sp1 = sequenceHandlerRunner.loadServiceProviderFromResource("get-cookie-test-sp.xml", this);

        AuthenticationContext context = sequenceHandlerRunner.createAuthenticationContext(sp1);

        SequenceConfig sequenceConfig = sequenceHandlerRunner.getSequenceConfig(context, sp1);
        context.setSequenceConfig(sequenceConfig);
        context.initializeAnalyticsData();

        JSONObject cookieValueJson = new JSONObject();
        cookieValueJson.put(HTTPConstants.VALUE, "test");
        cookieValueJson.put(HTTPConstants.SIGNATURE, null);
        String cookieValue = cookieValueJson.toString();
        Cookie cookie = new Cookie("name", Base64.encode(cookieValue.getBytes(Charsets.UTF_8)));
        Cookie mockCookie = Mockito.spy(cookie);
        Cookie[] cookies = {mockCookie};

        HttpServletRequest req = new MockServletRequestWithCookie(cookies);
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        context.addParameter(FrameworkConstants.RequestAttribute.HTTP_RESPONSE, new TransientObjectWrapper(resp));
        context.addParameter(FrameworkConstants.RequestAttribute.HTTP_REQUEST, new TransientObjectWrapper(req));
        sequenceHandlerRunner.handle(req, resp, context, "carbon.super");
        verify(mockCookie).getValue();
    }

    private class MockServletRequestWithCookie extends JsSequenceHandlerRunner.MockServletRequest {

        Cookie[] cookies;

        public MockServletRequestWithCookie(Cookie[] cookies) {

            super();
            this.cookies = cookies;
        }

        @Override
        public Cookie[] getCookies() {

            return this.cookies;
        }

    }
}
