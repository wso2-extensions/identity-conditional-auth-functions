/*
 *  Copyright (c) 2024, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.conditional.auth.functions.http.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.wso2.carbon.identity.application.authentication.framework.AsyncReturn;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.ConfigProvider;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants;
import org.wso2.carbon.identity.conditional.auth.functions.http.cache.APIAccessTokenCache;
import org.wso2.carbon.identity.secret.mgt.core.exception.SecretManagementClientException;
import org.wso2.carbon.identity.secret.mgt.core.exception.SecretManagementException;

import java.io.IOException;
import java.lang.reflect.Type;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.apache.http.HttpHeaders.ACCEPT;
import static org.apache.http.HttpHeaders.CONTENT_TYPE;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.CommonUtils.*;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.OUTCOME_FAIL;

/**
 * Implementation of the {@link AuthConfig}
 * This class is used to configure the client credential authentication.
 * The client credential is used to request the access token from the token endpoint.
 */
public class ClientCredentialAuthConfig implements AuthConfig {

    private static final Log LOG = LogFactory.getLog(ClientCredentialAuthConfig.class);
    private static final String TYPE_APPLICATION_JSON = "application/json";
    private static final String TYPE_FORM_DATA = "application/x-www-form-urlencoded";
    private static final String AUTHORIZATION = "Authorization";
    private static final String GRANT_TYPE = "grant_type";
    private static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
    private Gson gson;
    private static final String CONSUMER_KEY_VARIABLE_NAME = "consumerKey";
    private static final String CONSUMER_SECRET_VARIABLE_NAME = "consumerSecret";
    private static final String TOKEN_ENDPOINT = "tokenEndpoint";
    private static final String SCOPE = "scope";
    private AtomicInteger tokenRequestAttemptCountForTimeOut;
    private static final String ACCESS_TOKEN_KEY = "access_token";
    private static final String JWT_EXP_CLAIM = "exp";
    private static final String BEARER = "Bearer ";
    private static final String BASIC = "Basic ";
    private final int maxTokenRequestAttemptsForTimeOut = 2;
    private APIAccessTokenCache apiAccessTokenCache;
    private String consumerKey;
    private String consumerSecret;
    private String scopes;
    private String tokenEndpoint;
    private AuthenticationContext authenticationContext;
    private AsyncReturn asyncReturn;

    public void setAuthenticationContext(AuthenticationContext authenticationContext) {
        this.authenticationContext = authenticationContext;
    }

    public void setAsyncReturn(AsyncReturn asyncReturn) {
        this.asyncReturn = asyncReturn;
    }

    public AuthenticationContext getAuthenticationContext() {
        return authenticationContext;
    }

    /**
     * This method decodes access token and compare its expiry time with the current time to decide whether it's
     * expired.
     *
     * @param accessToken Access token which needs to be evaluated
     * @return A boolean value indicating whether the token is expired
     * @throws ParseException {@link ParseException}
     */
    private boolean isTokenExpired(String accessToken) throws ParseException {

        SignedJWT decodedToken = SignedJWT.parse(accessToken);
        Date expiryDate = (Date) decodedToken.getJWTClaimsSet().getClaim(JWT_EXP_CLAIM);
        LocalDateTime expiryTimestamp = LocalDateTime.ofInstant(expiryDate.toInstant(), ZoneId.systemDefault());
        return LocalDateTime.now().isAfter(expiryTimestamp);
    }

    public void setConsumerKey(String consumerKey) {
        this.consumerKey = consumerKey;
    }

    public void setConsumerSecret(String consumerSecret) {
        this.consumerSecret = consumerSecret;
    }

    public void setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    public void setScopes(String scopes) {
        this.scopes = scopes;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public String getConsumerKey() {
        return consumerKey;
    }

    public String getConsumerSecret() {
        return consumerSecret;
    }

    public String getScopes() {
        return scopes;
    }

    @Override
    public HttpUriRequest applyAuth(HttpUriRequest request, AuthConfigModel authConfigModel) throws FrameworkException {

        this.apiAccessTokenCache = APIAccessTokenCache.getInstance();
        Map<String, Object> properties = authConfigModel.getProperties();
        if (!properties.containsKey(CONSUMER_KEY_VARIABLE_NAME) || !properties.containsKey(CONSUMER_SECRET_VARIABLE_NAME) ||
                !properties.containsKey(TOKEN_ENDPOINT)) {
            asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
            LOG.error("Required properties not defined. Aborting token request.");
            return request;
        }
        if (!properties.containsKey(SCOPE)) {
            setScopes(null);
        } else {
            setScopes(properties.get(SCOPE).toString());
        }
        setConsumerKey(properties.get(CONSUMER_KEY_VARIABLE_NAME).toString());
        setConsumerSecret(properties.get(CONSUMER_SECRET_VARIABLE_NAME).toString());
        setTokenEndpoint(properties.get(TOKEN_ENDPOINT).toString());
        String accessToken = callTokenEndpoint(getAuthenticationContext());
        request.setHeader(AUTHORIZATION, BEARER + accessToken);
        return request;
    }

    /**
     * This method is used to request the access token from the token endpoint.
     *
     * @param authenticationContext {@link AuthenticationContext}
     * @return Access token
     * @throws FrameworkException {@link FrameworkException}
     */
    private String callTokenEndpoint(AuthenticationContext authenticationContext) throws FrameworkException {

        try {
            if (StringUtils.isEmpty(getTokenEndpoint())) {
                asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
                LOG.error("Token endpoint not defined. Aborting token request.");
                return null;
            }
            this.tokenRequestAttemptCountForTimeOut = new AtomicInteger(0);
            this.gson = new GsonBuilder().create();
            resolveConsumerKeySecrete();
            String accessToken = apiAccessTokenCache.getValueFromCache(getConsumerKey(),
                    authenticationContext.getTenantDomain());
            if (StringUtils.isNotEmpty(accessToken) && !isTokenExpired(accessToken)) {
                LOG.info("Unexpired access token available in cache. Session data key: " +
                        authenticationContext.getContextIdentifier());
                return accessToken;
            } else {
                LOG.info("Requesting the access token from external api token endpoint. Session data key: " +
                        authenticationContext.getContextIdentifier());
                accessToken = attemptAccessTokenRequest(maxTokenRequestAttemptsForTimeOut);
                if (accessToken == null) {
                    asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
                    LOG.error("Failed to obtain access token after " + maxTokenRequestAttemptsForTimeOut +
                            " attempts.");
                } else {
                    return accessToken;
                }
            }
        } catch (IllegalArgumentException e) {
            LOG.error("Invalid endpoint Url: " + getTokenEndpoint(), e);
            asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
        } catch (SecretManagementClientException e) {
            LOG.debug("Client error while resolving external api token endpoint consumer key or secret.", e);
            asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
        } catch (SecretManagementException e) {
            LOG.error("Error while resolving external api token endpoint consumer key or secret.", e);
            asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
        } catch (Exception e) {
            LOG.error("Error while invoking the conditional authentication function.", e);
            asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
        }
        return null;
    }

    /**
     * This method is used to attempt the access token request from the token endpoint.
     *
     * @param maxAttempts Maximum number of attempts to request the access token
     * @return Access token
     */
    private String attemptAccessTokenRequest(int maxAttempts) {

        AtomicInteger attemptCount = new AtomicInteger(0);

        while (attemptCount.incrementAndGet() <= maxAttempts) {
            try {
                LOG.info("Retrying token request for session data key: " +
                        this.authenticationContext.getContextIdentifier());
                String accessToken = requestAccessToken();
                if (accessToken != null) {
                    return accessToken;
                }
            } catch (IOException e) {
                LOG.error("Attempt " + attemptCount.get() + " failed.", e);
            } catch (FrameworkException e) {
                LOG.error("Error while getting HTTP client for calling the token endpoint. session data key: " +
                        authenticationContext.getContextIdentifier(), e);
            }

            LOG.info("Retrying token request. Attempt: " + attemptCount.get());
        }

        LOG.warn("Maximum token request attempts reached.");
        return null;
    }

    /**
     * This method is used to request the access token from the token endpoint.
     *
     * @return Access token
     * @throws IOException        {@link IOException}
     * @throws FrameworkException {@link FrameworkException}
     */
    private String requestAccessToken() throws IOException, FrameworkException {

        String outcome = Constants.OUTCOME_FAIL;
        HttpPost request = new HttpPost(tokenEndpoint);
        request.setHeader(ACCEPT, TYPE_APPLICATION_JSON);
        request.setHeader(CONTENT_TYPE, TYPE_FORM_DATA);

        request.setHeader(AUTHORIZATION, BASIC + Base64.getEncoder()
                .encodeToString((getConsumerKey() + ":" + getConsumerSecret())
                        .getBytes(StandardCharsets.UTF_8)));

        List<BasicNameValuePair> bodyParams = new ArrayList<>();
        bodyParams.add(new BasicNameValuePair(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS));
        if (StringUtils.isNotEmpty(getScopes())) {
            bodyParams.add(new BasicNameValuePair(SCOPE, getScopes()));
        }
        request.setEntity(new UrlEncodedFormEntity(bodyParams));

        RequestConfig config = RequestConfig.custom()
                .setConnectTimeout(ConfigProvider.getInstance().getConnectionTimeout())
                .setConnectionRequestTimeout(ConfigProvider.getInstance().getConnectionRequestTimeout())
                .setSocketTimeout(ConfigProvider.getInstance().getReadTimeout())
                .setRedirectsEnabled(false)
                .setRelativeRedirectsAllowed(false)
                .build();
        CloseableHttpClient client = HttpClientBuilder.create().setDefaultRequestConfig(config).build();

        try (CloseableHttpResponse response = client.execute(request)) {
            int responseCode;

            try {
                LOG.info("Access token response received.");
                responseCode = response.getStatusLine().getStatusCode();
                if (responseCode >= 200 && responseCode < 300) {
                    return processSuccessfulResponse(response);
                } else {
                    LOG.error("Failed to retrieve access token from external api token endpoint. Response Code: "
                            + responseCode + ". Session data key: " + authenticationContext.getContextIdentifier());
                }
            } catch (IOException e) {
                LOG.error("Failed to parse access token response to string. Session data key: " +
                        authenticationContext.getContextIdentifier(), e);
                outcome = Constants.OUTCOME_FAIL;
            } catch (Exception e) {
                LOG.error("Error occurred while handling the token response from external api token endpoint. " +
                        "Session data key: " + authenticationContext.getContextIdentifier(), e);
                outcome = Constants.OUTCOME_FAIL;
            }
        } catch (IllegalArgumentException e) {
            LOG.error("Invalid Url: " + tokenEndpoint, e);
            outcome = Constants.OUTCOME_FAIL;
        } catch (ConnectTimeoutException e) {
            LOG.error("Error while waiting to connect to " + tokenEndpoint, e);
            outcome = Constants.OUTCOME_TIMEOUT;
        } catch (SocketTimeoutException e) {
            LOG.error("Error while waiting for data from " + tokenEndpoint, e);
            outcome = Constants.OUTCOME_TIMEOUT;
        } catch (IOException e) {
            LOG.error("Error while calling endpoint. ", e);
            outcome = Constants.OUTCOME_FAIL;
        }
        asyncReturn.accept(authenticationContext, Collections.emptyMap(), outcome);
        return null;
    }

    /**
     * This method is used to process the successful response from the token endpoint.
     *
     * @param response {@link CloseableHttpResponse}
     * @return Access token
     * @throws IOException {@link IOException}
     */
    private String processSuccessfulResponse(CloseableHttpResponse response) throws IOException {

        Type responseBodyType = new TypeToken<Map<String, String>>(){}.getType();
        Map<String, String> responseBody = gson.fromJson(EntityUtils.toString(response.getEntity()), responseBodyType);
        String accessToken = responseBody.get(ACCESS_TOKEN_KEY);

        if (accessToken != null) {
            apiAccessTokenCache.addToCache(getConsumerKey(), accessToken,
                    this.authenticationContext.getTenantDomain());
            return accessToken;
        }
        LOG.error("Token response does not contain an access token. Session data key: " +
                authenticationContext.getContextIdentifier());
        return null;
    }

    /**
     * This method is used to resolve the consumer key and secret from the secret alias.
     *
     * @throws SecretManagementException {@link SecretManagementException}
     */
    public void resolveConsumerKeySecrete() throws SecretManagementException {

        if (StringUtils.isNotEmpty(getConsumerKey())) {
            if (!isSecretAlias(getConsumerKey())) {
                this.consumerKey = getConsumerKey();
            } else {
                String consumerKeyAlias = resolveSecretFromAlias(getConsumerKey());
                this.consumerKey = getResolvedSecret(consumerKeyAlias);
            }
        }

        if (StringUtils.isNotEmpty(getConsumerSecret())) {
            if (!isSecretAlias(getConsumerSecret())) {
                this.consumerSecret = getConsumerSecret();
            } else {
                String consumerSecretAlias = resolveSecretFromAlias(getConsumerSecret());
                this.consumerSecret = getResolvedSecret(consumerSecretAlias);
            }
        }

        if (StringUtils.isNotEmpty(getTokenEndpoint())) {
            this.tokenEndpoint = getTokenEndpoint();
        }
    }
}
