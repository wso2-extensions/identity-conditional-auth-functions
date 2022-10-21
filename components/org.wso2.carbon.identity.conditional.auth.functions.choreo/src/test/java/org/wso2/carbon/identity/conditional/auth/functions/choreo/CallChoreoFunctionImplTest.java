/*
 *  Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.choreo;

import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
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
import org.wso2.carbon.identity.common.testng.InjectMicroservicePort;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithMicroService;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.conditional.auth.functions.choreo.cache.AccessTokenCache;
import org.wso2.carbon.identity.conditional.auth.functions.choreo.internal.ChoreoFunctionServiceHolder;
import org.wso2.carbon.identity.conditional.auth.functions.common.internal.FunctionsDataHolder;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.ConfigProvider;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsSequenceHandlerAbstractTest;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsTestException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.service.RealmService;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

@WithCarbonHome
@WithMicroService
@WithH2Database(files = {"dbscripts/h2.sql"})
@WithRealmService(injectToSingletons = {IdentityTenantUtil.class, FrameworkServiceDataHolder.class})
@Path("/")
public class CallChoreoFunctionImplTest extends JsSequenceHandlerAbstractTest {

    private static final String FAILED = "FAILED";
    private static final String TOKEN_ENDPOINT_SUCCESS = "success";
    private static final String TOKEN_ENDPOINT_FAILURE = "failure";
    private static final String TOKEN_ENDPOINT_NO_TOKEN = "no-token";

    private static final AtomicInteger requestCount = new AtomicInteger(0);
    public static final String CHOREO_SERVICE_SUCCESS_PATH = "/dummyurl";
    public static final String CHOREO_SERVICE_EXPIRE_TOKEN_ONCE = "/token-expired-once";
    public static final String CHOREO_SERVICE_EXPIRE_TOKEN_ALWAYS = "/token-expired-always";
    public static final String CHOREO_TOKEN_FAILURE = "/token-failure";
    public static final String CHOREO_TOKEN_SUCCESS = "/token-success";

    @WithRealmService
    private RealmService realmService;

    @InjectMicroservicePort
    private int microServicePort;

    @BeforeMethod
    protected void setUp() throws Exception {

        super.setUp();

        sequenceHandlerRunner.registerJsFunction("callChoreo", new CallChoreoFunctionImpl());
        UserRealm userRealm = realmService.getTenantUserRealm(-1234);
        userRealm.getUserStoreManager().addRole("admin", new String[]{"admin", "test_user"}, null);

        FunctionsDataHolder functionsDataHolder = Mockito.mock(FunctionsDataHolder.class);
        Field functionsDataHolderInstance = FunctionsDataHolder.class.getDeclaredField("instance");
        functionsDataHolderInstance.setAccessible(true);
        functionsDataHolderInstance.set(null, functionsDataHolder);

        Field frameworkServiceDataHolderInstance = FrameworkServiceDataHolder.class.getDeclaredField("instance");
        frameworkServiceDataHolderInstance.setAccessible(true);
        FrameworkServiceDataHolder availableInstance = (FrameworkServiceDataHolder) frameworkServiceDataHolderInstance
                .get(null);
        ClientManager clientManager = new ClientManager();
        ChoreoFunctionServiceHolder.getInstance().setClientManager(clientManager);

        LongWaitStatusDAOImpl daoImpl = new LongWaitStatusDAOImpl();
        CacheBackedLongWaitStatusDAO cacheBackedDao = new CacheBackedLongWaitStatusDAO(daoImpl);
        int connectionTimeout = 5000;
        LongWaitStatusStoreService longWaitStatusStoreService =
                new LongWaitStatusStoreService(cacheBackedDao, connectionTimeout);
        availableInstance.setLongWaitStatusStoreService(longWaitStatusStoreService);
    }

    @AfterMethod
    private void cleanup() {
        AccessTokenCache.getInstance().clear("test_domain");
    }

    @DataProvider(name = "choreoEpValidity")
    public Object[][] getChoreoEpValidity() {

        return new Object[][]{
                {true},
                {false}
        };
    }

    @Test(dataProvider = "choreoEpValidity")
    public void testCallChoreoDomainValidity(boolean isValidChoreoDomain) throws JsTestException,
            NoSuchFieldException, IllegalAccessException {

        AuthenticationContext context = getAuthenticationContext(CHOREO_SERVICE_SUCCESS_PATH);

        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        if (isValidChoreoDomain) {
            // Setting localhost as the valid domain as
            // the unit test is calling a mock local endpoint.
            setChoreoDomain("localhost");
        } else {
            setChoreoDomain("abc");
        }
        setTokenEndpoint(TOKEN_ENDPOINT_SUCCESS);
        sequenceHandlerRunner.handle(req, resp, context, "carbon.super");

        if (isValidChoreoDomain) {
            assertNotNull(context.getSelectedAcr());
            assertEquals(context.getSelectedAcr(), "1", "Expected acr value not found");
        } else {
            assertEquals(context.getSelectedAcr(), FAILED, "Expected the request to fail");
        }
    }

    @Test
    public void testCallChoreUnsuccessfulTokenResponse() throws JsTestException,
            NoSuchFieldException, IllegalAccessException {

        AuthenticationContext context = getAuthenticationContext(CHOREO_SERVICE_SUCCESS_PATH);

        setChoreoDomain("localhost");
        setTokenEndpoint(TOKEN_ENDPOINT_FAILURE);

        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        sequenceHandlerRunner.handle(req, resp, context, "carbon.super");
        assertEquals(context.getSelectedAcr(), FAILED, "Expected the request to fail");
    }

    @Test
    public void testCallChoreTokenExpireOnce() throws JsTestException, NoSuchFieldException, IllegalAccessException {

        AuthenticationContext context = getAuthenticationContext(CHOREO_SERVICE_EXPIRE_TOKEN_ONCE);

        setChoreoDomain("localhost");
        setTokenEndpoint(TOKEN_ENDPOINT_SUCCESS);

        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        sequenceHandlerRunner.handle(req, resp, context, "carbon.super");
        assertEquals(context.getSelectedAcr(), "1", "Expected the request to fail");

    }

    @Test
    public void testCallChoreTokenExpireAlways() throws JsTestException, NoSuchFieldException, IllegalAccessException {

        AuthenticationContext context = getAuthenticationContext(CHOREO_SERVICE_EXPIRE_TOKEN_ALWAYS);

        setChoreoDomain("localhost");
        setTokenEndpoint(TOKEN_ENDPOINT_SUCCESS);

        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        sequenceHandlerRunner.handle(req, resp, context, "carbon.super");
        assertEquals(context.getSelectedAcr(), FAILED, "Expected the request to fail");
    }

    private AuthenticationContext getAuthenticationContext(String choreoServiceResourcePath) throws JsTestException {

        ServiceProvider sp1 = sequenceHandlerRunner.loadServiceProviderFromResource("risk-test-sp.xml", this);
        LocalAndOutboundAuthenticationConfig localAndOutboundAuthenticationConfig =
                sp1.getLocalAndOutBoundAuthenticationConfig();
        AuthenticationScriptConfig authenticationScriptConfig = localAndOutboundAuthenticationConfig
                .getAuthenticationScriptConfig();
        String content = authenticationScriptConfig.getContent();
        String newContent = String.format(content, microServicePort, choreoServiceResourcePath);
        authenticationScriptConfig.setContent(newContent);
        localAndOutboundAuthenticationConfig.setAuthenticationScriptConfig(authenticationScriptConfig);
        sp1.setLocalAndOutBoundAuthenticationConfig(localAndOutboundAuthenticationConfig);

        AuthenticationContext context = sequenceHandlerRunner.createAuthenticationContext(sp1);
        SequenceConfig sequenceConfig = sequenceHandlerRunner.getSequenceConfig(context, sp1);
        context.setSequenceConfig(sequenceConfig);
        context.initializeAnalyticsData();
        return context;
    }

    private void setChoreoDomain(String domain) {

        ConfigProvider.getInstance().getChoreoDomains().clear();
        ConfigProvider.getInstance().getChoreoDomains().add(domain);
    }

    private void setTokenEndpoint(String type) throws NoSuchFieldException, IllegalAccessException {

        final String tokenEndpoint;
        switch (type) {
            case TOKEN_ENDPOINT_FAILURE:
                tokenEndpoint = "http://localhost:%s/token-failure";
                break;
            case TOKEN_ENDPOINT_NO_TOKEN:
                tokenEndpoint = "http://localhost:%s/no-token";
                break;
            default:
                tokenEndpoint = "http://localhost:%s/token-success";
                break;
        }
        ConfigProvider instance = ConfigProvider.getInstance();
        Field choreoTokenEndpoint = ConfigProvider.class.getDeclaredField("choreoTokenEndpoint");
        choreoTokenEndpoint.setAccessible(true);
        choreoTokenEndpoint.set(instance, String.format(tokenEndpoint, microServicePort));
    }

    @POST
    @Path(CHOREO_SERVICE_SUCCESS_PATH)
    @Consumes("application/json")
    @Produces("application/json")
    public Map<String, String> choreoReceiver(Map<String, String> data) {

        Map<String, String> response = new HashMap<>();
        response.put("riskScore", "1");
        return response;
    }

    @POST
    @Path(CHOREO_TOKEN_SUCCESS)
    @Consumes("application/json")
    @Produces("application/json")
    public Map<String, String> choreoTokenEndpointSuccessResponse(Map<String, String> data) {

        Map<String, String> response = new HashMap<>();
        response.put("access_token", "eyJ4NXQiOiJNV1E1TldVd1lXWmlNbU16WlRJek16ZG1NekJoTVdNNFlqUXlNalZoTldNNE5qaGtNR1JtTnpGbE1HSTNaRGxtWW1Rek5tRXlNemhoWWpCaU5tWmhZdyIsImtpZCI6Ik1XUTVOV1V3WVdaaU1tTXpaVEl6TXpkbU16QmhNV000WWpReU1qVmhOV000Tmpoa01HUm1OekZsTUdJM1pEbG1ZbVF6Tm1FeU16aGhZakJpTm1aaFl3X1JTMjU2IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiIwYWFjM2Q0My1iNWNmLTQ2NDEtODkwMi03YWY4NjEzMzY0ZjQiLCJhdXQiOiJBUFBMSUNBVElPTiIsImF1ZCI6IjNFV095RHpaMXdhUDU0YWZFanVWNUgzMVFfZ2EiLCJuYmYiOjE2NjYyODUxNDYsImF6cCI6IjNFV095RHpaMXdhUDU0YWZFanVWNUgzMVFfZ2EiLCJzY29wZSI6ImRlZmF1bHQiLCJvcmdhbml6YXRpb24iOnsidXVpZCI6IjQyODA3ZTFmLTA3YmEtNGZiMC1hNmQyLWVjYzdiNDFkZDE0MyJ9LCJpc3MiOiJodHRwczpcL1wvc3RzLmNob3Jlby5kZXY6NDQzXC9vYXV0aDJcL3Rva2VuIiwiZXhwIjoxNjY2Mjg4NzQ2LCJpYXQiOjE2NjYyODUxNDYsImp0aSI6IjVkYjgzOTEyLWNlY2EtNGU1NC04MGJmLTFiNjAxNWYwZDIyMiJ9.QcSerNslaBJ_k2-nht7qoWh2Q-E4_B5J_9dPo_7jWzSkOZlpsmchnDG_2wL2JR1gEXGyoQg6akovQSGrafPpwQ7ONjqxaYqkFOnuSRLFhevyRWZ7TdnD7ShoZzcaSIF0yb68MpOwLjP87eAE_iHZJVwKYw1w2uHfdJI0VDVz1Q20qtpD1NhodfD5Hks1rXG-GGHwqXVdGwde1vGRGMtVDqSZ37G3b4XYtjMq0MfSni9o1WLPic357P9Y1QGmzrt0X2lCEcc4iy9oDOnfnVGdRMcbmJa7MbKrg1LlpbaK_PTKW1MofjQqTA-glqJGCdA32AiHrpwYkT0a_F2PQgQjD3mWWnKMejvfLPr2d0Ltwg7ykeaG1-3ZxrYo1inxtG5Hj5m8QcLdW43lFMJ6y6HPkc0DkjnwJwk-w-1dF7TkDn35zMXb4U2hBtXAIZsDEyhRCl-j_wRAbczrXCTykngfABhcKjIf5TDQye1zyeCtPMcUtql2lLF133bmRjB-Y4SvWzs00iVOnyN1EmoRGdb_k0yHojY1sURI5I553yykjtP3k7XAQYpNvMwZJC8p_avl6QE6n7VhaWU1ccRZZMe2gvTg1YQSr3qC4QRYwCUjqCpcrRou8pRZBJ9tYnEQRCk5XtNGLwzYUcsk1iGqhfa9G3mSI0WAqBMJO0G39sBS8V0");
        response.put("scope", "default");
        response.put("token_type", "Bearer");
        response.put("expires_in", "3600");
        return response;
    }

    @POST
    @Path(CHOREO_TOKEN_FAILURE)
    @Consumes("application/json")
    @Produces("application/json")
    public Response choreoTokenEndpointFailureResponse(Map<String, String> data) {

        Map<String, String> json = new HashMap<>();
        json.put("test", "value");
        return Response
                .status(Response.Status.INTERNAL_SERVER_ERROR)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .entity(json.toString())
                .build();
    }

    @POST
    @Path(CHOREO_SERVICE_EXPIRE_TOKEN_ONCE)
    @Consumes("application/json")
    @Produces("application/json")
    public Response choreoServiceEndpointTokenExpiredOnce(Map<String, String> data) {

        Map<String, String> responseBody = new HashMap<>();
        if (requestCount.get() == 0) {
            responseBody.put("code", "900901");
            requestCount.incrementAndGet();
            return Response
                    .status(Response.Status.UNAUTHORIZED)
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .entity(responseBody.toString())
                    .build();
        }

        responseBody.put("riskScore", "1");
        return Response.ok(responseBody.toString()).build();
    }

    @POST
    @Path(CHOREO_SERVICE_EXPIRE_TOKEN_ALWAYS)
    @Consumes("application/json")
    @Produces("application/json")
    public Response choreoServiceEndpointTokenExpiredAlways(Map<String, String> data) {

        Map<String, String> responseBody = new HashMap<>();
        responseBody.put("code", "900901");
        requestCount.incrementAndGet();
        return Response
                .status(Response.Status.UNAUTHORIZED)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .entity(responseBody.toString())
                .build();
    }
}
