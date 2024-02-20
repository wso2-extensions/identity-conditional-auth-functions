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
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.core.internal.CarbonCoreDataHolder;
import org.wso2.carbon.crypto.impl.DefaultCryptoService;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsServletRequest;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsServletResponse;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.nashorn.JsNashornServletRequest;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.nashorn.JsNashornServletResponse;
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

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.verify;

/**
 * Test for setCookie and get cookie
 */
@WithCarbonHome
@WithH2Database(files = {"dbscripts/h2.sql"})
@WithRealmService(injectToSingletons = FrameworkServiceDataHolder.class)
public class CookieFunctionImplTest extends JsSequenceHandlerAbstractTest {

    @BeforeMethod
    protected void setUp() throws Exception {

        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = true;
        sequenceHandlerRunner.registerJsFunction("setCookie", new SetCookieFunctionImpl());
        sequenceHandlerRunner.registerJsFunction("getCookieValue", new GetCookieFunctionImpl());
        DefaultCryptoService defaultCryptoService = new DefaultCryptoService();
        defaultCryptoService.registerInternalCryptoProvider(new SimpleCryptoProviderTest());
        CarbonCoreDataHolder.getInstance().setCryptoService(defaultCryptoService);
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

    @Test(dataProvider = "cookieValues")
    public void testWithSpecialCharactersWithEncryption(String inputCookieValue) throws JsTestException {

        boolean shouldEncrypt = true;
        boolean shouldSign = false;
        boolean shouldDecrypt = true;
        System.setProperty("org.wso2.CipherTransformation", "RSA");
        internalTestSetAndGetCookieValues(inputCookieValue, shouldEncrypt, shouldDecrypt, shouldSign);
    }

    @Test(dataProvider = "cookieValues")
    public void testWithSpecialCharactersNoEncryption(String inputCookieValue) throws JsTestException {

        boolean shouldEncrypt = false;
        boolean shouldSign = false;
        boolean shouldDecrypt = false;
        internalTestSetAndGetCookieValues(inputCookieValue, shouldEncrypt, shouldDecrypt, shouldSign);
    }

    @DataProvider(name = "cookieValues")
    public Object[][] getCookieValues() {

        return new Object[][]{
                {"Test"},
                {"1234"},
                {"Test1234"},
                {"asgh@123&*()!@#$"},
                {"{\"usr\" : \"" + "JohnDoe" + "\", \"str\" : \"" + "PRIMARY" + "\"}"}
        };
    }

    private void internalTestSetAndGetCookieValues(String inputCookieValue, boolean shouldEncrypt,
                                                   boolean shouldDecrypt, boolean shouldSign) throws JsTestException {

        GetCookieFunctionImpl getCookieFunction = new GetCookieFunctionImpl();
        SetCookieFunctionImpl setCookieFunction = new SetCookieFunctionImpl();

        String name = "test";

        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();
        JsServletResponse jsServletResponse = new JsNashornServletResponse(new TransientObjectWrapper(resp));
        Map<String, Object> setCookieParams = new HashMap<>();
        setCookieParams.put(HTTPConstants.ENCRYPT, shouldEncrypt);
        setCookieParams.put(HTTPConstants.SIGN, shouldSign);
        // Set the Cookie value.
        setCookieFunction.setCookie(jsServletResponse, name, inputCookieValue, setCookieParams);

        // Get the cookie value that added to the response when setCookie method value is called.
        ArgumentCaptor<Cookie> argumentCaptor = ArgumentCaptor.forClass(Cookie.class);
        verify(resp).addCookie(argumentCaptor.capture());
        Cookie cookie = new Cookie(name,argumentCaptor.getValue().getValue());
        Cookie mockCookie = Mockito.spy(cookie);
        Cookie[] cookies = {mockCookie};

        HttpServletRequest req = new MockServletRequestWithCookie(cookies);
        JsServletRequest jsServletRequest = new JsNashornServletRequest(new TransientObjectWrapper(req));
        Map<String, Object> getCookieParams = new HashMap<>();
        getCookieParams.put(HTTPConstants.DECRYPT, shouldDecrypt);
        // Get the cookie value
        String value = getCookieFunction.getCookieValue(jsServletRequest, name, getCookieParams );

        Assert.assertEquals(value, inputCookieValue);
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
