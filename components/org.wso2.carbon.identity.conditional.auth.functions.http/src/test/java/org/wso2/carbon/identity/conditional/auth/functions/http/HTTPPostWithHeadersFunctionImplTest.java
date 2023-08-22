/*
 *  Copyright (c) 2021, WSO2 Inc. (http://www.wso2.com).
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.http;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.dao.impl.CacheBackedLongWaitStatusDAO;
import org.wso2.carbon.identity.application.authentication.framework.dao.impl.LongWaitStatusDAOImpl;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.store.LongWaitStatusStoreService;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.script.AuthenticationScriptConfig;
import org.wso2.carbon.identity.common.testng.*;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.ConfigProvider;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsSequenceHandlerAbstractTest;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsTestException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;

import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.assertEquals;

@WithCarbonHome
@WithMicroService
@WithH2Database(files = {"dbscripts/h2_http.sql"})
@WithRealmService(injectToSingletons = {IdentityTenantUtil.class, FrameworkServiceDataHolder.class})
@Path("/")
public class HTTPPostWithHeadersFunctionImplTest extends JsSequenceHandlerAbstractTest {

    private static final String TEST_SP_CONFIG = "http-post-with-headers-test-sp.xml";
    private static final String JS_FUNCTION_NAME = "httpPostWithHeaders";
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String STATUS = "status";
    private static final String SUCCESS = "SUCCESS";
    private static final String FAILED = "FAILED";
    private static final String ALLOWED_DOMAIN = "abc";
    private static final String AUTHORIZATION = "Authorization";
    private static final String AUTHORIZATION_HEADER_VALUE = "Bearer your-token";
    private static final String EMAIL = "email";

    @InjectMicroservicePort
    private int microServicePort;

    @BeforeClass
    protected void initClass() throws Exception {

        super.setUp();
        LongWaitStatusDAOImpl daoImpl = new LongWaitStatusDAOImpl();
        CacheBackedLongWaitStatusDAO cacheBackedDao = new CacheBackedLongWaitStatusDAO(daoImpl);
        int connectionTimeout = 5000;
        LongWaitStatusStoreService longWaitStatusStoreService =
                new LongWaitStatusStoreService(cacheBackedDao, connectionTimeout);
        FrameworkServiceDataHolder.getInstance().setLongWaitStatusStoreService(longWaitStatusStoreService);
        sequenceHandlerRunner.registerJsFunction(JS_FUNCTION_NAME, new HTTPPostWithHeadersFunctionImpl());
    }

    @AfterClass
    protected void tearDown() {

        unsetAllowedDomains();
    }

    /**
     * Tests if the
     * @throws JsTestException
     */
    @Test
    public void testHttpPostWithHeadersMethod() throws JsTestException {

        String requestUrl = getRequestUrl();
        String result = executeHttpPostFunction(requestUrl);

        assertEquals(result, SUCCESS, "The http post request was not successful. Result from request: " + result);
    }

    @Test(dependsOnMethods = {"testHttpPostWithHeadersMethod"})
    public void testHttpPostWithHeadersMethodUrlValidation() throws JsTestException, NoSuchFieldException, IllegalAccessException {

        setAllowedDomain(ALLOWED_DOMAIN);
        String requestUrl = getRequestUrl();
        String result = executeHttpPostFunction(requestUrl);

        assertEquals(result, FAILED, "The http post request should fail but it was successful. Result from request: "
                + result);
    }

    private void setAllowedDomain(String domain) {

        ConfigProvider.getInstance().getAllowedDomainsForHttpFunctions().add(domain);
    }

    private void unsetAllowedDomains() {

        ConfigProvider.getInstance().getAllowedDomainsForHttpFunctions().clear();
    }

    private String getRequestUrl() {

        return "http://localhost:" + microServicePort + "/dummy-post-with-headers";
    }

    private String executeHttpPostFunction(String requestUrl) throws JsTestException {

        ServiceProvider sp = sequenceHandlerRunner.loadServiceProviderFromResource(TEST_SP_CONFIG, this);
        updateSPAuthScriptRequestUrl(sp, requestUrl);

        AuthenticationContext context = sequenceHandlerRunner.createAuthenticationContext(sp);
        SequenceConfig sequenceConfig = sequenceHandlerRunner.getSequenceConfig(context, sp);
        context.setSequenceConfig(sequenceConfig);
        context.initializeAnalyticsData();

        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        sequenceHandlerRunner.handle(req, resp, context, TENANT_DOMAIN);

        // Using selected acr as a mechanism to relay the
        // auth script execution state back to the context.
        return context.getSelectedAcr();
    }

    private void updateSPAuthScriptRequestUrl(ServiceProvider sp, String url) {

        LocalAndOutboundAuthenticationConfig localAndOutboundAuthenticationConfig =
                sp.getLocalAndOutBoundAuthenticationConfig();
        AuthenticationScriptConfig authenticationScriptConfig = localAndOutboundAuthenticationConfig
                .getAuthenticationScriptConfig();
        String script = authenticationScriptConfig.getContent();
        authenticationScriptConfig.setContent(String.format(script, url));
        localAndOutboundAuthenticationConfig.setAuthenticationScriptConfig(authenticationScriptConfig);
        sp.setLocalAndOutBoundAuthenticationConfig(localAndOutboundAuthenticationConfig);
    }

    @POST
    @Path("/dummy-post-with-headers")
    @Produces("application/json")
    @Consumes("application/json")
    public Map<String, String> dummyPostWithHeaders(@HeaderParam(AUTHORIZATION) String authorization, Map<String, String> data) {

        Map<String, String> response = new HashMap<>();
        if (authorization != null && authorization.equals(AUTHORIZATION_HEADER_VALUE) && data.containsKey(EMAIL)) {
            response.put(STATUS, SUCCESS);
        } else {
            response.put(STATUS, FAILED);
        }
        return response;
    }
}
