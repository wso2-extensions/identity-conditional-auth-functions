/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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
import org.apache.http.client.methods.HttpUriRequest;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.AsyncReturn;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.central.log.mgt.internal.CentralLogMgtServiceComponentHolder;
import org.wso2.carbon.identity.common.testng.InjectMicroservicePort;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithMicroService;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.ConfigProvider;
import org.wso2.carbon.identity.conditional.auth.functions.http.cache.APIAccessTokenExpiryCache;
import org.wso2.carbon.identity.conditional.auth.functions.http.cache.CachedToken;
import org.wso2.carbon.identity.conditional.auth.functions.http.util.AuthConfigModel;
import org.wso2.carbon.identity.conditional.auth.functions.http.util.ClientCredentialAuthConfig;
import org.wso2.carbon.identity.event.services.IdentityEventService;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for {@link ClientCredentialAuthConfig}.
 * <p>
 * An embedded MSF4J microservice (this class itself) acts as the token endpoint so that
 * real HTTP round-trips can be exercised without an external server.
 * The {@link APIAccessTokenExpiryCache} singleton is replaced with a Mockito mock for each
 * test, giving full control over cache hit/miss scenarios.
 */
@WithCarbonHome
@WithMicroService
@Path("/")
public class ClientCredentialAuthConfigTest {

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String CONSUMER_KEY = "testClientId";
    private static final String CONSUMER_SECRET = "testClientSecret";
    private static final String OPAQUE_TOKEN = "opaque_token_abc123xyz";
    private static final int EXPIRES_IN_SECONDS = 3600;

    @InjectMicroservicePort
    private int microServicePort;

    private APIAccessTokenExpiryCache mockExpiryCache;
    private MockedStatic<APIAccessTokenExpiryCache> mockedCacheStatic;
    private MockedStatic<ConfigProvider> mockedConfigStatic;

    private AuthenticationContext mockAuthContext;
    private AsyncReturn mockAsyncReturn;

    @BeforeClass
    public void setUpClass() {

        IdentityEventService identityEventService = mock(IdentityEventService.class);
        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(identityEventService);
    }

    @AfterClass
    public void tearDownClass() {

        CentralLogMgtServiceComponentHolder.getInstance().setIdentityEventService(null);
    }

    @BeforeMethod
    public void setUp() {

        mockExpiryCache = mock(APIAccessTokenExpiryCache.class);
        mockedCacheStatic = mockStatic(APIAccessTokenExpiryCache.class);
        mockedCacheStatic.when(APIAccessTokenExpiryCache::getInstance).thenReturn(mockExpiryCache);
        when(mockExpiryCache.getValueFromCache(anyString(), anyString())).thenReturn(null);

        ConfigProvider mockConfigProvider = mock(ConfigProvider.class);
        when(mockConfigProvider.getRequestRetryCount()).thenReturn(2);
        when(mockConfigProvider.getConnectionTimeout()).thenReturn(5000);
        when(mockConfigProvider.getConnectionRequestTimeout()).thenReturn(5000);
        when(mockConfigProvider.getReadTimeout()).thenReturn(5000);
        mockedConfigStatic = mockStatic(ConfigProvider.class);
        mockedConfigStatic.when(ConfigProvider::getInstance).thenReturn(mockConfigProvider);

        mockAuthContext = mock(AuthenticationContext.class);
        when(mockAuthContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);
        when(mockAuthContext.getContextIdentifier()).thenReturn("test-session-key");

        mockAsyncReturn = mock(AsyncReturn.class);
    }

    @AfterMethod
    public void tearDown() {

        mockedCacheStatic.close();
        mockedConfigStatic.close();
    }

    @DataProvider(name = "missingRequiredProperties")
    public Object[][] missingRequiredProperties() {

        return new Object[][]{
                {"consumerKey"},
                {"consumerSecret"},
                {"tokenEndpoint"},
        };
    }

    @DataProvider(name = "failingTokenEndpoints")
    public Object[][] failingTokenEndpoints() {

        return new Object[][]{
                {"token-endpoint-4xx"},
                {"token-endpoint-5xx"},
                {"token-endpoint-no-access-token"},
        };
    }

    private String tokenEndpointUrl(String path) {

        return "http://localhost:" + microServicePort + "/" + path;
    }

    private AuthConfigModel buildAuthConfigModel(String tokenEndpointUrl) {

        Map<String, Object> props = new HashMap<>();
        props.put("consumerKey", CONSUMER_KEY);
        props.put("consumerSecret", CONSUMER_SECRET);
        props.put("tokenEndpoint", tokenEndpointUrl);
        return new AuthConfigModel("clientcredential", props);
    }

    private AuthConfigModel buildAuthConfigModelMissingProperty(String missingProperty) {

        Map<String, Object> props = new HashMap<>();
        props.put("consumerKey", CONSUMER_KEY);
        props.put("consumerSecret", CONSUMER_SECRET);
        props.put("tokenEndpoint", tokenEndpointUrl("jwt-token-endpoint"));
        props.remove(missingProperty);
        return new AuthConfigModel("clientcredential", props);
    }

    private String generateJwt(int expiresInSeconds) throws JOSEException {

        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyID("test-key-id")
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT)
                .keyID("test-key-id")
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://test.example.com/oauth2/token")
                .subject("test-subject")
                .expirationTime(Date.from(Instant.now().plusSeconds(expiresInSeconds)))
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new RSASSASigner(rsaKey));
        return jwt.serialize();
    }

    private void applyAuth(HttpUriRequest request, AuthConfigModel authConfigModel) throws FrameworkException {

        when(request.getMethod()).thenReturn("POST");
        ClientCredentialAuthConfig config = new ClientCredentialAuthConfig();
        config.setAuthenticationContext(mockAuthContext);
        config.setAsyncReturn(mockAsyncReturn);
        config.applyAuth(request, authConfigModel);
    }

    @Test(dataProvider = "missingRequiredProperties",
            expectedExceptions = FrameworkException.class,
            expectedExceptionsMessageRegExp = "Missing required properties.")
    public void testApplyAuthMissingRequiredPropertyThrowsFrameworkException(String missingProperty)
            throws FrameworkException {

        applyAuth(mock(HttpUriRequest.class), buildAuthConfigModelMissingProperty(missingProperty));
    }

    @Test
    public void testApplyAuthJwtTokenSetsAuthorizationBearerHeader() throws FrameworkException {

        HttpUriRequest request = mock(HttpUriRequest.class);
        applyAuth(request, buildAuthConfigModel(tokenEndpointUrl("jwt-token-endpoint")));

        ArgumentCaptor<String> valueCaptor = ArgumentCaptor.forClass(String.class);
        verify(request).setHeader(eq("Authorization"), valueCaptor.capture());
        assertTrue(valueCaptor.getValue().startsWith("Bearer "),
                "Authorization header must start with 'Bearer '");
    }

    /**
     * When a JWT token is returned by the token endpoint, a {@link CachedToken} must be
     * stored in the cache with the correct consumer key and tenant domain.
     * The cached token's expiry must be in the future (not expired).
     */
    @Test
    public void testApplyAuthJwtTokenIsCachedWithFutureExpiry() throws FrameworkException {

        HttpUriRequest request = mock(HttpUriRequest.class);
        applyAuth(request, buildAuthConfigModel(tokenEndpointUrl("jwt-token-endpoint")));

        ArgumentCaptor<CachedToken> tokenCaptor = ArgumentCaptor.forClass(CachedToken.class);
        verify(mockExpiryCache).addToCache(eq(CONSUMER_KEY), tokenCaptor.capture(), eq(TENANT_DOMAIN));

        CachedToken cached = tokenCaptor.getValue();
        assertNotNull(cached, "A CachedToken must have been stored.");
        assertNotNull(cached.getAccessToken(), "CachedToken must carry the access token string.");
        assertFalse(cached.isExpired(), "Newly cached token must not be expired.");
    }

    /**
     * The expiry epoch of the cached JWT token must be derived from its {@code exp} claim,
     * not from the {@code expires_in} response field.
     */
    @Test
    public void testApplyAuthJwtTokenExpiryEpochDerivedFromJwtExpClaim() throws FrameworkException {

        HttpUriRequest request = mock(HttpUriRequest.class);
        long beforeCall = Instant.now().getEpochSecond();
        applyAuth(request, buildAuthConfigModel(tokenEndpointUrl("jwt-token-endpoint")));

        ArgumentCaptor<CachedToken> tokenCaptor = ArgumentCaptor.forClass(CachedToken.class);
        verify(mockExpiryCache).addToCache(any(), tokenCaptor.capture(), any());

        long expiryEpoch = tokenCaptor.getValue().getExpiryEpoch();
        assertTrue(expiryEpoch >= beforeCall + EXPIRES_IN_SECONDS - 5,
                "Expiry epoch should be approximately now + 3600s.");
        assertTrue(expiryEpoch <= beforeCall + EXPIRES_IN_SECONDS + 5,
                "Expiry epoch should be approximately now + 3600s.");
    }

    /**
     * When the cache contains an unexpired token, it must be returned directly without
     * making any HTTP call to the token endpoint.
     */
    @Test
    public void testApplyAuthUnexpiredCachedTokenReturnsCachedTokenWithoutHttpCall() throws FrameworkException {

        String cachedAccessToken = "cached_jwt_access_token";
        CachedToken unexpired = new CachedToken(cachedAccessToken,
                Instant.now().getEpochSecond() + EXPIRES_IN_SECONDS);
        when(mockExpiryCache.getValueFromCache(eq(CONSUMER_KEY), eq(TENANT_DOMAIN))).thenReturn(unexpired);

        HttpUriRequest request = mock(HttpUriRequest.class);
        // Point at a non-existent path — if an HTTP call is made the test will fail.
        applyAuth(request, buildAuthConfigModel(tokenEndpointUrl("nonexistent-token-endpoint")));

        ArgumentCaptor<String> valueCaptor = ArgumentCaptor.forClass(String.class);
        verify(request).setHeader(eq("Authorization"), valueCaptor.capture());
        assertEquals(valueCaptor.getValue(), "Bearer " + cachedAccessToken,
                "Must use the cached token, not fetch a new one.");
        verify(mockExpiryCache, never()).addToCache(anyString(), any(), anyString());
    }

    /**
     * When the cache holds an expired token, a fresh token must be fetched from the
     * token endpoint and the cache must be updated with the new entry.
     */
    @Test
    public void testApplyAuthExpiredCachedTokenFetchesAndCachesNewToken() throws FrameworkException {

        CachedToken expired = new CachedToken("expired_token", Instant.now().getEpochSecond() - 10);
        when(mockExpiryCache.getValueFromCache(anyString(), anyString())).thenReturn(expired);

        HttpUriRequest request = mock(HttpUriRequest.class);
        applyAuth(request, buildAuthConfigModel(tokenEndpointUrl("jwt-token-endpoint")));

        ArgumentCaptor<CachedToken> tokenCaptor = ArgumentCaptor.forClass(CachedToken.class);
        verify(mockExpiryCache).addToCache(eq(CONSUMER_KEY), tokenCaptor.capture(), eq(TENANT_DOMAIN));
        assertFalse(tokenCaptor.getValue().isExpired(), "Newly fetched token must not be expired.");

        ArgumentCaptor<String> headerCaptor = ArgumentCaptor.forClass(String.class);
        verify(request).setHeader(eq("Authorization"), headerCaptor.capture());
        assertFalse(headerCaptor.getValue().contains("expired_token"),
                "Authorization header must not carry the expired token.");
    }

    /**
     * When the token endpoint returns an opaque token together with {@code expires_in},
     * the token must be cached and the Authorization header set correctly.
     */
    @Test
    public void testApplyAuthOpaqueTokenWithExpiresInCachesTokenAndSetsHeader() throws FrameworkException {

        HttpUriRequest request = mock(HttpUriRequest.class);
        applyAuth(request, buildAuthConfigModel(tokenEndpointUrl("opaque-token-endpoint-with-expiry")));

        ArgumentCaptor<CachedToken> tokenCaptor = ArgumentCaptor.forClass(CachedToken.class);
        verify(mockExpiryCache).addToCache(eq(CONSUMER_KEY), tokenCaptor.capture(), eq(TENANT_DOMAIN));

        CachedToken cached = tokenCaptor.getValue();
        assertEquals(cached.getAccessToken(), OPAQUE_TOKEN,
                "Cached token must match the opaque token returned by the endpoint.");
        assertFalse(cached.isExpired(), "Cached opaque token with expires_in must not be expired.");

        ArgumentCaptor<String> headerCaptor = ArgumentCaptor.forClass(String.class);
        verify(request).setHeader(eq("Authorization"), headerCaptor.capture());
        assertEquals(headerCaptor.getValue(), "Bearer " + OPAQUE_TOKEN);
    }

    /**
     * The expiry epoch for an opaque token with {@code expires_in} must be computed as
     * {@code now + expires_in} (not derived from JWT parsing).
     */
    @Test
    public void testApplyAuthOpaqueTokenWithExpiresInExpiryComputedFromExpiresIn() throws FrameworkException {

        HttpUriRequest request = mock(HttpUriRequest.class);
        long beforeCall = Instant.now().getEpochSecond();
        applyAuth(request, buildAuthConfigModel(tokenEndpointUrl("opaque-token-endpoint-with-expiry")));

        ArgumentCaptor<CachedToken> tokenCaptor = ArgumentCaptor.forClass(CachedToken.class);
        verify(mockExpiryCache).addToCache(any(), tokenCaptor.capture(), any());

        long expiryEpoch = tokenCaptor.getValue().getExpiryEpoch();
        assertTrue(expiryEpoch >= beforeCall + EXPIRES_IN_SECONDS - 5,
                "Expiry epoch must be approximately now + expires_in.");
        assertTrue(expiryEpoch <= beforeCall + EXPIRES_IN_SECONDS + 5,
                "Expiry epoch must be approximately now + expires_in.");
    }

    /**
     * When the token endpoint returns an opaque token with no {@code expires_in},
     * the token must NOT be cached (per RFC 6749 §4.2.2), but the Authorization header
     * must still be set so the current request succeeds.
     */
    @Test
    public void testApplyAuthOpaqueTokenWithoutExpiresInSkipsCacheButSetsHeader() throws FrameworkException {

        HttpUriRequest request = mock(HttpUriRequest.class);
        applyAuth(request, buildAuthConfigModel(tokenEndpointUrl("opaque-token-endpoint-no-expiry")));

        verify(mockExpiryCache, never()).addToCache(anyString(), any(), anyString());

        ArgumentCaptor<String> headerCaptor = ArgumentCaptor.forClass(String.class);
        verify(request).setHeader(eq("Authorization"), headerCaptor.capture());
        assertEquals(headerCaptor.getValue(), "Bearer " + OPAQUE_TOKEN,
                "Bearer header must carry the opaque token even when it is not cached.");
    }

    /**
     * When called twice with a no-expiry opaque token, the second call must also
     * reach the token endpoint (no stale cache entry is reused).
     */
    @Test
    public void testApplyAuthOpaqueTokenWithoutExpiresInSecondCallAlsoFetchesToken() throws FrameworkException {

        HttpUriRequest request1 = mock(HttpUriRequest.class);
        applyAuth(request1, buildAuthConfigModel(tokenEndpointUrl("opaque-token-endpoint-no-expiry")));

        when(mockExpiryCache.getValueFromCache(anyString(), anyString())).thenReturn(null);
        HttpUriRequest request2 = mock(HttpUriRequest.class);
        applyAuth(request2, buildAuthConfigModel(tokenEndpointUrl("opaque-token-endpoint-no-expiry")));

        verify(request1).setHeader(eq("Authorization"), eq("Bearer " + OPAQUE_TOKEN));
        verify(request2).setHeader(eq("Authorization"), eq("Bearer " + OPAQUE_TOKEN));
        verify(mockExpiryCache, never()).addToCache(anyString(), any(), anyString());
    }

    /**
     * A 4xx response must not be retried; a 5xx response must be retried up to the configured
     * limit; a response missing {@code access_token} must also fail. All must throw a
     * FrameworkException.
     */
    @Test(dataProvider = "failingTokenEndpoints",
            expectedExceptions = FrameworkException.class,
            expectedExceptionsMessageRegExp = "Failed to retrieve access token.")
    public void testApplyAuthFailingEndpointThrowsFrameworkException(String endpointPath) throws FrameworkException {

        applyAuth(mock(HttpUriRequest.class), buildAuthConfigModel(tokenEndpointUrl(endpointPath)));
    }

    @POST
    @Path("/jwt-token-endpoint")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    public Map<String, String> jwtTokenEndpoint(@FormParam("grant_type") String grantType) throws JOSEException {

        Map<String, String> response = new HashMap<>();
        response.put("access_token", generateJwt(EXPIRES_IN_SECONDS));
        response.put("token_type", "Bearer");
        response.put("expires_in", String.valueOf(EXPIRES_IN_SECONDS));
        return response;
    }

    @POST
    @Path("/opaque-token-endpoint-with-expiry")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    public Map<String, String> opaqueTokenEndpointWithExpiry(@FormParam("grant_type") String grantType) {

        Map<String, String> response = new HashMap<>();
        response.put("access_token", OPAQUE_TOKEN);
        response.put("token_type", "Bearer");
        response.put("expires_in", String.valueOf(EXPIRES_IN_SECONDS));
        return response;
    }

    @POST
    @Path("/opaque-token-endpoint-no-expiry")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    public Map<String, String> opaqueTokenEndpointNoExpiry(@FormParam("grant_type") String grantType) {

        Map<String, String> response = new HashMap<>();
        response.put("access_token", OPAQUE_TOKEN);
        response.put("token_type", "Bearer");
        return response;
    }

    @POST
    @Path("/token-endpoint-4xx")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    public Response tokenEndpoint4xx() {

        return Response.status(Response.Status.BAD_REQUEST).build();
    }

    @POST
    @Path("/token-endpoint-5xx")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    public Response tokenEndpoint5xx() {

        return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
    }

    @POST
    @Path("/token-endpoint-no-access-token")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("application/json")
    public Map<String, String> tokenEndpointNoAccessToken(@FormParam("grant_type") String grantType) {

        Map<String, String> response = new HashMap<>();
        response.put("token_type", "Bearer");
        response.put("expires_in", "3600");
        return response;
    }
}
