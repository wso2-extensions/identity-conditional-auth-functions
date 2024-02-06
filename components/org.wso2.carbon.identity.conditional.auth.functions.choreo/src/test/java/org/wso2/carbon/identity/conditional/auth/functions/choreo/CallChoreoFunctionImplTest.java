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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
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
import org.wso2.carbon.identity.conditional.auth.functions.choreo.cache.ChoreoAccessTokenCache;
import org.wso2.carbon.identity.conditional.auth.functions.choreo.internal.ChoreoFunctionServiceHolder;
import org.wso2.carbon.identity.conditional.auth.functions.common.internal.FunctionsDataHolder;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.ConfigProvider;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsSequenceHandlerAbstractTest;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsTestException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.service.RealmService;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.Date;
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

    private static final Log LOG = LogFactory.getLog(CallChoreoFunctionImplTest.class);
    private static final String FAILED = "FAILED";
    private static final String TOKEN_ENDPOINT_SUCCESS = "success";
    private static final String TOKEN_ENDPOINT_FAILURE = "failure";
    private static final AtomicInteger requestCount = new AtomicInteger(0);
    private static final String CHOREO_SERVICE_SUCCESS_PATH = "/choreo-service-success";
    private static final String CHOREO_SERVICE_EXPIRE_TOKEN_ONCE = "/choreo-service-token-expired-once";
    private static final String CHOREO_SERVICE_EXPIRE_TOKEN_ALWAYS = "/choreo-service-token-expired-always";
    private static final String CHOREO_TOKEN_FAILURE = "/token-failure";
    private static final String CHOREO_TOKEN_SUCCESS = "/token-success";
    private static final String TENANT_DOMAIN = "test_domain";
    private static final String CONSUMER_KEY = "dummyKey";
    private static final String CONSUMER_SECRET = "dummySecret";

    @WithRealmService
    private RealmService realmService;

    @InjectMicroservicePort
    private int microServicePort;

    @BeforeMethod
    protected void setUp() throws Exception {

        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = true;
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

        // Increase socket timeout duration to avoid intermittent failures due to socket timeouts.
       Field httpReadTimeout = ClientManager.class.getDeclaredField("httpReadTimeout");
       httpReadTimeout.setAccessible(true);
       httpReadTimeout.setInt(null, 5000);
    }

    @AfterMethod
    private void cleanup() {

        ChoreoAccessTokenCache.getInstance().clear(TENANT_DOMAIN);
        requestCount.set(0);
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

        LOG.info("===== Testing callChoreo domain validity. Is valid domain: " + isValidChoreoDomain);
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

        LOG.info("===== Testing callChoreo unsuccessful token response");
        AuthenticationContext context = getAuthenticationContext(CHOREO_SERVICE_SUCCESS_PATH);

        setChoreoDomain("localhost");
        setTokenEndpoint(TOKEN_ENDPOINT_FAILURE);

        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        sequenceHandlerRunner.handle(req, resp, context, "carbon.super");
        assertEquals(context.getSelectedAcr(), FAILED, "Expected the request to fail");
    }

    @Test
    public void testCallChoreoExpiredTokenInCache()
            throws JsTestException, NoSuchFieldException, IllegalAccessException, JOSEException {

        LOG.info("===== Testing callChoreo expired token in cache");

        // set an expired token to the cache.
        ChoreoAccessTokenCache.getInstance().addToCache(CONSUMER_KEY, generateTestAccessToken(true), TENANT_DOMAIN);

        AuthenticationContext context = getAuthenticationContext(CHOREO_SERVICE_SUCCESS_PATH);
        setChoreoDomain("localhost");
        setTokenEndpoint(TOKEN_ENDPOINT_SUCCESS);

        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        sequenceHandlerRunner.handle(req, resp, context, "carbon.super");
        assertEquals(context.getSelectedAcr(), "1", "Expected the request to fail");

    }

    @Test
    public void testCallChoreTokenExpireOnce() throws JsTestException, NoSuchFieldException, IllegalAccessException {

        LOG.info("===== Testing callChoreo token expire once");
        AuthenticationContext context = getAuthenticationContext(CHOREO_SERVICE_EXPIRE_TOKEN_ONCE);

        setChoreoDomain("localhost");
        setTokenEndpoint(TOKEN_ENDPOINT_SUCCESS);

        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        sequenceHandlerRunner.handle(req, resp, context, "carbon.super");
        assertEquals(context.getSelectedAcr(), "1", "Expected acr value not found");

    }

    @Test
    public void testCallChoreTokenExpireAlways() throws JsTestException, NoSuchFieldException, IllegalAccessException {

        LOG.info("===== Testing callChoreo token expire always");
        AuthenticationContext context = getAuthenticationContext(CHOREO_SERVICE_EXPIRE_TOKEN_ALWAYS);

        setChoreoDomain("localhost");
        setTokenEndpoint(TOKEN_ENDPOINT_SUCCESS);

        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        sequenceHandlerRunner.handle(req, resp, context, "carbon.super");
        assertEquals(context.getSelectedAcr(), FAILED, "Expected the request to fail");
    }

    @Test
    public void testCallChoreCachingToken() throws JsTestException, NoSuchFieldException, IllegalAccessException {

        LOG.info("===== Testing caching token");

        // Clear access token cache to ensure there are no residual values from other tests.
        ChoreoAccessTokenCache.getInstance().clear(TENANT_DOMAIN);

        AuthenticationContext context = getAuthenticationContext(CHOREO_SERVICE_SUCCESS_PATH);
        setChoreoDomain("localhost");
        setTokenEndpoint(TOKEN_ENDPOINT_SUCCESS);

        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

        sequenceHandlerRunner.handle(req, resp, context, "carbon.super");
        assertNotNull(ChoreoAccessTokenCache.getInstance().getValueFromCache(CONSUMER_KEY, TENANT_DOMAIN));
        assertEquals(context.getSelectedAcr(), "1", "Expected acr value not found");

        // Making another authentication attempt using new authentication context, request and a response to
        // simulate a subsequent login attempt.
        AuthenticationContext secondContext = getAuthenticationContext(CHOREO_SERVICE_SUCCESS_PATH);

        // Set token endpoint to the endpoint which returns a failure response to make sure an access token request
        // will not receive a valid response. The second authentication attempt will only succeed if there was a valid
        // token in the cache.
        setTokenEndpoint(TOKEN_ENDPOINT_FAILURE);

        HttpServletRequest secondRequest = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse secondResponse = sequenceHandlerRunner.createHttpServletResponse();

        sequenceHandlerRunner.handle(secondRequest, secondResponse, secondContext, "carbon.super");
        assertEquals(secondContext.getSelectedAcr(), "1", "Expected acr value not found");

    }

    /**
     * Create and returns an authentication context.
     *
     * @param choreoServiceResourcePath The resource path of the Choreo service that needs to be invoked.
     * @return An authentication context.
     * @throws JsTestException {@link JsTestException}
     */
    private AuthenticationContext getAuthenticationContext(String choreoServiceResourcePath) throws JsTestException {

        ServiceProvider sp1 = sequenceHandlerRunner.loadServiceProviderFromResource("risk-test-sp.xml", this);
        LocalAndOutboundAuthenticationConfig localAndOutboundAuthenticationConfig =
                sp1.getLocalAndOutBoundAuthenticationConfig();
        AuthenticationScriptConfig authenticationScriptConfig = localAndOutboundAuthenticationConfig
                .getAuthenticationScriptConfig();
        String content = authenticationScriptConfig.getContent();
        String newContent = String.format(content, microServicePort, choreoServiceResourcePath,
                CONSUMER_KEY, CONSUMER_SECRET);
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

    /**
     * Set the URL for the Choreo token endpoint.
     *
     * @param type The type of the response expected by the token endpoint.
     * @throws NoSuchFieldException {@link NoSuchFieldException}
     * @throws IllegalAccessException {@link IllegalAccessException}
     */
    private void setTokenEndpoint(String type) throws NoSuchFieldException, IllegalAccessException {

        final String tokenEndpoint;
        if (TOKEN_ENDPOINT_FAILURE.equals(type)) {
            tokenEndpoint = "http://localhost:%s/token-failure";
        } else {
            tokenEndpoint = "http://localhost:%s/token-success";
        }
        ConfigProvider instance = ConfigProvider.getInstance();
        Field choreoTokenEndpoint = ConfigProvider.class.getDeclaredField("choreoTokenEndpoint");
        choreoTokenEndpoint.setAccessible(true);
        choreoTokenEndpoint.set(instance, String.format(tokenEndpoint, microServicePort));
    }

    /**
     * Generates a JSON Web Token for testing purposes.
     *
     * @param isExpired Whether the JWT should be expired.
     */
    private String generateTestAccessToken(boolean isExpired) throws JOSEException {

        Instant instant = isExpired ? Instant.now().minusSeconds(3600) : Instant.now().plusSeconds(3600);
        RSAKey senderJWK = new RSAKeyGenerator(2048)
                .keyID("123")
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT)
                .keyID("MWQ5NWUwYWZiMmMzZTIzMzdmMzBhMWM4YjQyMjVhNWM4NjhkMGRmNzFlMGI3ZDlmYmQzNmEyMzhhYjBiNmZhYw_RS256")
                .build();
        JWTClaimsSet payload = new JWTClaimsSet.Builder()
                .issuer("https://sts.choreo.dev:443/oauth2/token")
                .audience("3ENOyHzZtwaP54apEjuV5H31Q_gb")
                .subject("0aac3d44-b5tf-4641-8902-7af8713364f8")
                .expirationTime(Date.from(instant))
                .build();

        SignedJWT signedJWT = new SignedJWT(header, payload);
        signedJWT.sign(new RSASSASigner(senderJWK));
        return signedJWT.serialize();
    }

    /**
     * This endpoint always returns a 200 OK response with the expected payload from the Choreo API in the response
     * body.
     * Simulates a scenario where the call to the Choreo API succeed.
     *
     * @param data request payload
     */
    @POST
    @Path(CHOREO_SERVICE_SUCCESS_PATH)
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, String> choreoReceiver(Map<String, String> data) {

        Map<String, String> response = new HashMap<>();
        response.put("riskScore", "1");
        return response;
    }

    /**
     * This endpoint always returns a 200 OK response with an access token that has not been expired.
     * Simulates a scenario where the call to the Choreo token endpoint succeed.
     * @throws JOSEException {@link JOSEException}
     */
    @POST
    @Path(CHOREO_TOKEN_SUCCESS)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, String> choreoTokenEndpointSuccessResponse() throws JOSEException {

        Map<String, String> response = new HashMap<>();
        response.put("access_token", generateTestAccessToken(false));
        response.put("scope", "default");
        response.put("token_type", "Bearer");
        response.put("expires_in", "3600");
        return response;
    }

    /**
     * This endpoint always returns a 500 internal server error response.
     * Simulates a scenario where the call to the Choreo token endpoint failing for some reason.
     */
    @POST
    @Path(CHOREO_TOKEN_FAILURE)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response choreoTokenEndpointFailureResponse() {

        Map<String, String> json = new HashMap<>();
        json.put("test", "value");
        return Response
                .status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(json.toString())
                .build();
    }

    /**
     * This endpoint returns a 401 unauthorized response with error code 900901 (sent by Choreo when tokens
     * are inactive) in the response body for the first request. For the subsequent requests, it returns 200 OK
     * with expected payload from Choreo API in the response body.
     *
     * Simulates a situation where the call to invoke the Choreo API fails due to an expired token, and succeeds after
     * generating a new token.
     *
     * @param data request payload
     */
    @POST
    @Path(CHOREO_SERVICE_EXPIRE_TOKEN_ONCE)
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response choreoServiceEndpointTokenExpiredOnce(Map<String, String> data) {

        Map<String, String> responseBody = new HashMap<>();
        if (requestCount.get() == 0) {
            responseBody.put("code", "900901");
            requestCount.incrementAndGet();
            return Response
                    .status(Response.Status.UNAUTHORIZED)
                    .entity(responseBody.toString())
                    .build();
        }

        responseBody.put("riskScore", "1");
        return Response.ok(responseBody.toString()).build();
    }

    /**
     * This endpoint always return a 401 unauthorized response with error code 900901 (sent by Choreo when tokens
     * are inactive) in the response body.
     *
     * Simulates a situation where the call to invoke the Choreo API fails due to an expired token, and the newly
     * generated token is also expired.
     *
     * @param data request payload
     */
    @POST
    @Path(CHOREO_SERVICE_EXPIRE_TOKEN_ALWAYS)
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response choreoServiceEndpointTokenExpiredAlways(Map<String, String> data) {

        Map<String, String> responseBody = new HashMap<>();
        responseBody.put("code", "900901");
        requestCount.incrementAndGet();
        return Response
                .status(Response.Status.UNAUTHORIZED)
                .entity(responseBody.toString())
                .build();
    }
}
