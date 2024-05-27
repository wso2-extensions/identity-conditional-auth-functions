/*
 *  Copyright (c) 2021, WSO2 LLC. (http://www.wso2.com).
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
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Parameters;
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
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.ConfigProvider;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsSequenceHandlerAbstractTest;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsTestException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

import java.util.Date;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.POST;
import javax.ws.rs.Produces;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.doNothing;
import static org.testng.Assert.assertEquals;

@WithCarbonHome
@WithMicroService
@WithH2Database(files = {"dbscripts/h2_http.sql"})
@WithRealmService(injectToSingletons = {IdentityTenantUtil.class, FrameworkServiceDataHolder.class})
@Path("/")
public class HTTPPostFunctionImplTest extends JsSequenceHandlerAbstractTest {

    private static final String TEST_SP_CONFIG = "http-post-test-sp.xml";
    private static final String TEST_HEADERS = "http-post-test-headers.xml";
    private static final String TEST_AUTH_CONFIG_WITH_APIKEY = "http-post-test-auth-config-with-apikey.xml";
    private static final String TEST_AUTH_CONFIG_WITH_BEARERTOKEN = "http-post-test-auth-config-with-bearertoken.xml";
    private static final String TEST_AUTH_CONFIG_WITH_BASICAUTH = "http-post-test-auth-config-with-basicauth.xml";
    private static final String TEST_AUTH_CONFIG_WITH_CLIENTCREDENTIAL = "http-post-test-auth-config-with-clientcredential.xml";
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String STATUS = "status";
    private static final String SUCCESS = "SUCCESS";
    private static final String FAILED = "FAILED";
    private static final String EMAIL = "email";
    private static final String ALLOWED_DOMAIN = "abc";
    private static final String AUTHORIZATION = "Authorization";
    private static final String API_KEY_HEADER = "X-API-KEY";
    private HTTPPostFunctionImpl httpPostFunction;

    @InjectMicroservicePort
    private int microServicePort;

    @BeforeClass
    @Parameters({"scriptEngine"})
    protected void initClass(String scriptEngine) throws Exception {

        super.setUp(scriptEngine);
        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = true;
        LongWaitStatusDAOImpl daoImpl = new LongWaitStatusDAOImpl();
        CacheBackedLongWaitStatusDAO cacheBackedDao = new CacheBackedLongWaitStatusDAO(daoImpl);
        int connectionTimeout = 5000;
        LongWaitStatusStoreService longWaitStatusStoreService =
                new LongWaitStatusStoreService(cacheBackedDao, connectionTimeout);
        FrameworkServiceDataHolder.getInstance().setLongWaitStatusStoreService(longWaitStatusStoreService);
        sequenceHandlerRunner.registerJsFunction("httpPost", new HTTPPostFunctionImpl());

        // Mocking the executeHttpMethod method to avoid actual http calls.
        httpPostFunction = spy(new HTTPPostFunctionImpl());
        doNothing().when(httpPostFunction).executeHttpMethod(any(), any(), any());
    }

    @AfterClass
    protected void tearDown() {

        unsetAllowedDomains();
    }

    @AfterMethod
    protected void tearDownTest() {

        reset(httpPostFunction);
    }

    @Test
    public void testHttpPostMethod() throws JsTestException {

        String result = executeHttpPostFunction("dummy-post", TEST_SP_CONFIG);

        assertEquals(result, SUCCESS, "The http post request was not successful. Result from request: " + result);
    }

    @Test(dependsOnMethods = {"testHttpPostMethod"})
    public void testHttpPostMethodUrlValidation() throws JsTestException, NoSuchFieldException, IllegalAccessException {

        setAllowedDomain(ALLOWED_DOMAIN);
        String result = executeHttpPostFunction("dummy-post", TEST_SP_CONFIG);

        assertEquals(result, FAILED, "The http post request should fail but it was successful. Result from request: "
                + result);
    }

    /**
     * Test httpPost with headers.
     * Check if the headers are sent with the request.
     *
     * @throws JsTestException
     */
    @Test
    public void testHttpPostWithHeaders() throws JsTestException {

        String result = executeHttpPostFunction("dummy-post-with-headers", TEST_HEADERS);
        assertEquals(result, SUCCESS, "The http post request was not successful. Result from request: "
                + result);
    }

    /**
     * Test httpPost method with basicauth auth config.
     * Check if the auth config is applied to the request.
     *
     * @throws JsTestException
     */
    @Test
    public void testHttpPostMethodWithBasicAuthAuthConfig() throws JsTestException {

        String result = executeHttpPostFunction("dummy-post-with-basicauth-auth-config",
                TEST_AUTH_CONFIG_WITH_BASICAUTH);

        assertEquals(result, SUCCESS,
                "The http post request was not successful with basicauth auth config. Result from request: " +
                        result);
    }

    /**
     * Test httpPost method with apikey auth config.
     * Check if the auth config is applied to the request.
     *
     * @throws JsTestException
     */
    @Test
    public void testHttpPostMethodWithApiKeyAuthAuthConfig() throws JsTestException {

        String result = executeHttpPostFunction("dummy-post-with-apikey-auth-config", TEST_AUTH_CONFIG_WITH_APIKEY);

        assertEquals(result, SUCCESS,
                "The http post request was not successful with apikey auth config. Result from request: " +
                        result);
    }

    /**
     * Test httpPost method with bearertoken auth config.
     * Check if the auth config is applied to the request.
     *
     * @throws JsTestException
     */
    @Test
    public void testHttpPostMethodWithBearerTokenAuthConfig() throws JsTestException {

        String result = executeHttpPostFunction("dummy-post-with-bearertoken-auth-config",
                TEST_AUTH_CONFIG_WITH_BEARERTOKEN);

        assertEquals(result, SUCCESS,
                "The http post request was not successful with bearertoken auth config. Result from request: " +
                        result);
    }

    /**
     * Test httpPost method with clientcredential auth config.
     * Check if the auth config is applied to the request.
     *
     * @throws JsTestException
     */
    @Test
    public void testHttpPostMethodWithClientCredentialAuthConfig() throws JsTestException {

        String result = executeHttpPostFunction("dummy-post-with-clientcredential-auth-config",
                TEST_AUTH_CONFIG_WITH_CLIENTCREDENTIAL);

        assertEquals(result, SUCCESS,
                "The http post request was not successful with clientcredential auth config. Result from request: " +
                        result);
    }

    /**
     * Tests the behavior of the httpPost function when provided with null headers.
     *
     * @throws IllegalArgumentException if the provided arguments are not valid.
     */
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testHttpPostWithNullHeaders() {

        Map<String, Object> payloadData = new HashMap<>();
        Map<String, Object> eventHandlers = new HashMap<>();
        httpPostFunction.httpPost(getRequestUrl("dummy-post"), payloadData, null, eventHandlers);
    }

    /**
     * Tests the behavior of the httpPost function when provided with invalid number of arguments.
     *
     * @throws IllegalArgumentException if the provided arguments are not valid.
     */
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testHttpPostWithInvalidNumberOfArguments() {

        Map<String, Object> payloadData = new HashMap<>();
        Map<String, Object> headers = new HashMap<>();
        Map<String, Object> eventHandlers = new HashMap<>();
        httpPostFunction.httpPost(getRequestUrl("dummy-post"), payloadData, headers, eventHandlers, eventHandlers);
    }

    private void setAllowedDomain(String domain) {

        ConfigProvider.getInstance().getAllowedDomainsForHttpFunctions().add(domain);
    }

    private void unsetAllowedDomains() {

        ConfigProvider.getInstance().getAllowedDomainsForHttpFunctions().clear();
    }

    private String getRequestUrl(String path) {

        return "http://localhost:" + microServicePort + "/" + path;
    }

    private String executeHttpPostFunction(String path, String adaptiveAuthScript) throws JsTestException {

        ServiceProvider sp = sequenceHandlerRunner.loadServiceProviderFromResource(adaptiveAuthScript, this);
        updateSPAuthScriptRequestUrl(sp, path);

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

    private void updateSPAuthScriptRequestUrl(ServiceProvider sp, String path) {

        LocalAndOutboundAuthenticationConfig localAndOutboundAuthenticationConfig =
                sp.getLocalAndOutBoundAuthenticationConfig();
        AuthenticationScriptConfig authenticationScriptConfig = localAndOutboundAuthenticationConfig
                .getAuthenticationScriptConfig();
        String script = authenticationScriptConfig.getContent();
        authenticationScriptConfig.setContent(getFormattedScript(script, path));
        localAndOutboundAuthenticationConfig.setAuthenticationScriptConfig(authenticationScriptConfig);
        sp.setLocalAndOutBoundAuthenticationConfig(localAndOutboundAuthenticationConfig);
    }

    private String getFormattedScript(String script, String path) {
        switch (path) {
            case "dummy-post":
                return String.format(script, getRequestUrl("dummy-post"));
            case "dummy-post-with-headers":
                return String.format(script, getRequestUrl("dummy-post-with-headers"));
            case "dummy-post-with-basicauth-auth-config":
                return String.format(script, getRequestUrl("dummy-post-with-basicauth-auth-config"));
            case "dummy-post-with-apikey-auth-config":
                return String.format(script, getRequestUrl("dummy-post-with-apikey-auth-config"));
            case "dummy-post-with-bearertoken-auth-config":
                return String.format(script, getRequestUrl("dummy-post-with-bearertoken-auth-config"));
            case "dummy-post-with-clientcredential-auth-config":
                return String.format(script, getRequestUrl("dummy-post-with-clientcredential-auth-config"),
                        getRequestUrl("dummy-token-endpoint"));
            default:
                return null;
        }
    }

    /**
     * Generates a JSON Web Token for testing purposes.
     */
    private String generateTestAccessToken() throws JOSEException {

        Instant instant = Instant.now().plusSeconds(3600);
        RSAKey senderJWK = new RSAKeyGenerator(2048)
                .keyID("123")
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT)
                .keyID("MWQ5NWUwYWZiMmMzZTIzMzdmMzBhMWM4YjQyMjVhNWM4NjhkMGRmNzFlMGI3ZDlmYmQzNmEyMzhhYjBiNmZhYw_RS256")
                .build();
        JWTClaimsSet payload = new JWTClaimsSet.Builder()
                .issuer("https://test/oauth2/token")
                .audience("3ENOyHzZtwaP54apEjuV5H31Q_gb")
                .subject("0aac3d44-b5tf-4641-8902-7af8713364f8")
                .expirationTime(Date.from(instant))
                .build();

        SignedJWT signedJWT = new SignedJWT(header, payload);
        signedJWT.sign(new RSASSASigner(senderJWK));
        return signedJWT.serialize();
    }

    @POST
    @Path("/dummy-post")
    @Produces("application/json")
    @Consumes("application/json")
    public Map<String, String> dummyPost(Map<String, String> data) {

        Map<String, String> response = new HashMap<>();
        if (data.containsKey(EMAIL)) {
            response.put(STATUS, SUCCESS);
        } else {
            response.put(STATUS, FAILED);
        }
        return response;
    }

    /**
     * Dummy post method to test payload and headers.
     * Check if the payload data and headers are sent with the request.
     * @param authorization
     * @param data
     * @return
     */
    @POST
    @Path("/dummy-post-with-headers")
    @Produces("application/json")
    @Consumes("application/json")
    public Map<String, String> dummyPostWithHeaders(@HeaderParam(AUTHORIZATION) String authorization, Map<String, String> data) {

        Map<String, String> response = new HashMap<>();
        if (data.containsKey(EMAIL) && authorization != null) {
            response.put(STATUS, SUCCESS);
        } else {
            response.put(STATUS, FAILED);
        }
        return response;
    }

    /**
     * Dummy endpoint to test the http post function with basicauth auth config.
     *
     * @param authorization Authorization header value.
     * @return Response.
     */
    @POST
    @Path("/dummy-post-with-basicauth-auth-config")
    @Produces("application/json")
    public Map<String, String> dummyPostWithBasicAuthAuthConfig(@HeaderParam(AUTHORIZATION) String authorization, Map<String, String> data) {

        Map<String, String> response = new HashMap<>();
        if (data.containsKey(EMAIL) && authorization != null) {
            response.put(STATUS, SUCCESS);
        } else {
            response.put(STATUS, FAILED);
        }
        return response;
    }

    /**
     * Dummy endpoint to test the http post function with apikey auth config.
     *
     * @param apikeyHeader apikey header value.
     * @return Response.
     */
    @POST
    @Path("/dummy-post-with-apikey-auth-config")
    @Produces("application/json")
    public Map<String, String> dummyPostWithApiKeyAuthConfig(@HeaderParam(API_KEY_HEADER) String apikeyHeader, Map<String, String> data) {

        Map<String, String> response = new HashMap<>();
        if (data.containsKey(EMAIL) && apikeyHeader != null) {
            response.put(STATUS, SUCCESS);
        } else {
            response.put(STATUS, FAILED);
        }
        return response;
    }

    /**
     * Dummy endpoint to test the http post function with bearertoken auth config.
     *
     * @param authorization authorization header value.
     * @return Response.
     */
    @POST
    @Path("/dummy-post-with-bearertoken-auth-config")
    @Produces("application/json")
    public Map<String, String> dummyPostWithBearerTokenAuthConfig(@HeaderParam(AUTHORIZATION) String authorization, Map<String, String> data) {

        Map<String, String> response = new HashMap<>();
        if (data.containsKey(EMAIL) && authorization.startsWith("Bearer")) {
            response.put(STATUS, SUCCESS);
        } else {
            response.put(STATUS, FAILED);
        }
        return response;
    }

    /**
     * Dummy endpoint to test the http post function with clientcredential auth config.
     *
     * @param authorization authorization header value.
     * @return Response.
     */
    @POST
    @Path("/dummy-post-with-clientcredential-auth-config")
    @Produces("application/json")
    public Map<String, String> dummyPostWithClientCredentialAuthConfig(@HeaderParam(AUTHORIZATION) String authorization, Map<String, String> data) {

        Map<String, String> response = new HashMap<>();
        if (data.containsKey(EMAIL) && authorization.startsWith("Bearer")) {
            response.put(STATUS, SUCCESS);
        } else {
            response.put(STATUS, FAILED);
        }
        return response;
    }

    /**
     * Dummy token endpoint to test the http post function with clientcredential auth config.
     *
     * @param authorization authorization header value.
     * @return Response.
     */
    @POST
    @Path("/dummy-token-endpoint")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    public Map<String, String> dummyTokenEndpoint(@HeaderParam("Authorization") String authorization,
                                                  @FormParam("grant_type") String grantType) throws JOSEException {

        Map<String, String> response = new HashMap<>();
        if (grantType.equals("client_credentials")) {
            response.put("access_token", generateTestAccessToken());
            response.put("scope", "default");
            response.put("token_type", "Bearer");
            response.put("expires_in", "3600");
            return response;
        } else {
            response.put(STATUS, FAILED);
        }
        return response;
    }
}
