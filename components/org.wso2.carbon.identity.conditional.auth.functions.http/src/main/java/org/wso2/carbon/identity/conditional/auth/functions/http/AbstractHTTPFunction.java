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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.identity.application.authentication.framework.AsyncProcess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsGraphBuilder;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.ConfigProvider;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants;
import org.wso2.carbon.identity.conditional.auth.functions.http.util.AuthConfig;
import org.wso2.carbon.identity.conditional.auth.functions.http.util.AuthConfigFactory;
import org.wso2.carbon.identity.conditional.auth.functions.http.util.AuthConfigModel;
import org.wso2.carbon.utils.DiagnosticLog;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.apache.http.HttpHeaders.ACCEPT;

/**
 * Abstract class for handling http calls.
 */
public abstract class AbstractHTTPFunction {

    private static final Log LOG = LogFactory.getLog(AbstractHTTPFunction.class);
    protected static final String TYPE_APPLICATION_JSON = "application/json";
    protected static final String TYPE_APPLICATION_FORM_URLENCODED = "application/x-www-form-urlencoded";
    protected static final String TYPE_TEXT_PLAIN = "text/plain";
    private static final char DOMAIN_SEPARATOR = '.';
    private static final String RESPONSE = "response";
    private static final int HTTP_STATUS_UNAUTHORIZED = 401;
    private static final int HTTP_STATUS_OK = 200;
    private static final int HTTP_STATUS_MULTIPLE_CHOICES = 300;
    private static final int HTTP_STATUS_TOO_MANY_REQUESTS = 429;
    private static final int HTTP_STATUS_REQUEST_TIMEOUT = 408;
    private static final int HTTP_STATUS_INTERNAL_SERVER_ERROR = 500;
    private static final int HTTP_STATUS_BAD_REQUEST = 400;
    private int maxRequestAttemptsForAPIEndpointTimeout;
    private final List<String> allowedDomains;

    private CloseableHttpClient client;

    public AbstractHTTPFunction() {

        maxRequestAttemptsForAPIEndpointTimeout = ConfigProvider.getInstance().
                getMaxRequestAttemptsForAPIEndpointTimeout();
        RequestConfig config = RequestConfig.custom()
                .setConnectTimeout(ConfigProvider.getInstance().getConnectionTimeout())
                .setConnectionRequestTimeout(ConfigProvider.getInstance().getConnectionRequestTimeout())
                .setSocketTimeout(ConfigProvider.getInstance().getReadTimeout())
                .setRedirectsEnabled(false)
                .setRelativeRedirectsAllowed(false)
                .build();
        client = HttpClientBuilder.create().setDefaultRequestConfig(config).build();
        allowedDomains = ConfigProvider.getInstance().getAllowedDomainsForHttpFunctions();
    }

    protected void executeHttpMethod(HttpUriRequest clientRequest, Map<String, Object> eventHandlers,
                                     AuthConfigModel authConfigModel) {

        AsyncProcess asyncProcess = new AsyncProcess((context, asyncReturn) -> {
            String outcome;
            String endpointURL = null;

            HttpUriRequest request;
            try {
                if (authConfigModel != null) {
                    AuthConfig authConfig = AuthConfigFactory.getAuthConfig(authConfigModel, context, asyncReturn);
                    request = authConfig.applyAuth(clientRequest, authConfigModel);
                } else {
                    request = clientRequest;
                }

                if (request.getURI() != null) {
                    endpointURL = request.getURI().toString();
                }

                if (!isValidRequestDomain(request.getURI())) {
                    LOG.error("Provided Url does not contain a allowed domain. Invalid Url: " + endpointURL);
                    asyncReturn.accept(context, Collections.emptyMap(), Constants.OUTCOME_FAIL);
                } else {
                    Pair<Integer, Pair<String, JSONObject>> result = executeRequest(request, endpointURL);
                    if (result.getLeft() != HTTP_STATUS_TOO_MANY_REQUESTS &&
                            result.getLeft() != HTTP_STATUS_UNAUTHORIZED &&
                            !result.getRight().getLeft().equals(Constants.OUTCOME_SUCCESS)) {
                        LOG.error("Error while calling endpoint. Url: " + endpointURL);
                        result = executeRequestWithRetries(request, endpointURL, maxRequestAttemptsForAPIEndpointTimeout);
                    }
                    outcome = result.getRight().getLeft();
                    JSONObject json = result.getRight().getRight();
                    asyncReturn.accept(context, json != null ? json : Collections.emptyMap(), outcome);
                }
            } catch (Exception e) {
                LOG.error("Error while applying authentication to the request.", e);
                asyncReturn.accept(context, Collections.emptyMap(), Constants.OUTCOME_FAIL);
            }
        });
        JsGraphBuilder.addLongWaitProcess(asyncProcess, eventHandlers);
    }

    /**
     * Execute the request with retries.
     *
     * @param request     HttpUriRequest.
     * @param endpointURL Endpoint URL.
     * @param maxRetries  Maximum number of retries.
     * @return Pair of outcome and json.
     */
    private Pair<Integer, Pair<String, JSONObject>> executeRequestWithRetries
    (HttpUriRequest request, String endpointURL, int maxRetries) {

        Pair<Integer, Pair<String, JSONObject>> result = Pair.of(0, Pair.of(Constants.OUTCOME_FAIL, null));
        JSONObject json = null;
        String outcome = Constants.OUTCOME_FAIL;
        int attempts = 0;

        while (attempts < maxRetries) {
            attempts++;
            LOG.warn("Retrying the request. Attempt: " + attempts + " for endpoint: " + endpointURL);
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                        DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                        Constants.LogConstants.ActionIDs.RECEIVE_API_RESPONSE);
                diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.EXTERNAL_API, endpointURL)
                        .resultMessage("Retrying the request for external endpoint.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            result = executeRequest(request, endpointURL);
            if (result.getLeft() == HTTP_STATUS_TOO_MANY_REQUESTS || result.getLeft() == HTTP_STATUS_UNAUTHORIZED ||
                    result.getRight().getLeft().equals(Constants.OUTCOME_SUCCESS)) {
                return result;
            }
        }
        return Pair.of(result.getLeft(), Pair.of(outcome, json));
    }

    /**
     * Execute the request.
     *
     * @param request     HttpUriRequest.
     * @param endpointURL Endpoint URL.
     * @return Pair of outcome and json.
     */
    private Pair<Integer, Pair<String, JSONObject>> executeRequest(HttpUriRequest request, String endpointURL) {

        JSONObject json = null;
        String outcome;
        int statuscode;

        try (CloseableHttpResponse response = client.execute(request)) {
            int responseCode = response.getStatusLine().getStatusCode();
            if (responseCode >= HTTP_STATUS_OK && responseCode < HTTP_STATUS_MULTIPLE_CHOICES) {
                statuscode = HTTP_STATUS_OK;
                if (response.getEntity() != null) {
                    Header contentType = response.getEntity().getContentType();
                    String jsonString = EntityUtils.toString(response.getEntity());
                    if (contentType != null && contentType.getValue().contains(TYPE_TEXT_PLAIN)) {
                        json = new JSONObject();
                        json.put(RESPONSE, jsonString);
                    } else {
                        JSONParser parser = new JSONParser();
                        json = (JSONObject) parser.parse(jsonString);
                    }
                }
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                            DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            Constants.LogConstants.ActionIDs.RECEIVE_API_RESPONSE);
                    diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.EXTERNAL_API, endpointURL)
                            .resultMessage("Successfully called the external endpoint.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                outcome = Constants.OUTCOME_SUCCESS;
                return Pair.of(statuscode, Pair.of(outcome, json)); // Success, return immediately
            } else if (responseCode == HTTP_STATUS_UNAUTHORIZED) {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                            DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            Constants.LogConstants.ActionIDs.RECEIVE_API_RESPONSE);
                    diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.EXTERNAL_API, endpointURL)
                            .resultMessage("Received 401 response from external API call.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                LOG.warn("Received 401 response from external API call. Url: " + endpointURL);
                outcome = Constants.OUTCOME_FAIL;
                return Pair.of(HTTP_STATUS_UNAUTHORIZED, Pair.of(outcome, null)); // Unauthorized, no retry
            } else if (responseCode == HTTP_STATUS_REQUEST_TIMEOUT) {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                            DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            Constants.LogConstants.ActionIDs.RECEIVE_API_RESPONSE);
                    diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.EXTERNAL_API, endpointURL)
                            .resultMessage("Received 408 response from external API call.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                outcome = Constants.OUTCOME_TIMEOUT;
                statuscode = HTTP_STATUS_REQUEST_TIMEOUT; // Timeout, retry if attempts left
            } else if (responseCode == HTTP_STATUS_TOO_MANY_REQUESTS) {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                            DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            Constants.LogConstants.ActionIDs.RECEIVE_API_RESPONSE);
                    diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.EXTERNAL_API, endpointURL)
                            .resultMessage("Received 429 response from external API call.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                outcome = Constants.OUTCOME_FAIL;
                statuscode = HTTP_STATUS_TOO_MANY_REQUESTS; // Rate limited, no retry
                return Pair.of(statuscode, Pair.of(outcome, null));
            } else if (responseCode >= HTTP_STATUS_INTERNAL_SERVER_ERROR) {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                            DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            Constants.LogConstants.ActionIDs.RECEIVE_API_RESPONSE);
                    diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.EXTERNAL_API, endpointURL)
                            .resultMessage("Received 5xx response from external API call.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                outcome = Constants.OUTCOME_FAIL;
                statuscode = HTTP_STATUS_INTERNAL_SERVER_ERROR; // Server error, retry if attempts left
            } else if (responseCode >= HTTP_STATUS_BAD_REQUEST) {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                            DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            Constants.LogConstants.ActionIDs.RECEIVE_API_RESPONSE);
                    diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.EXTERNAL_API, endpointURL)
                            .resultMessage("Received 4xx response from external API call.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                outcome = Constants.OUTCOME_FAIL;
                statuscode = HTTP_STATUS_BAD_REQUEST; // Client error, retry if attempts left
            } else {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                            DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            Constants.LogConstants.ActionIDs.RECEIVE_API_RESPONSE);
                    diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.EXTERNAL_API, endpointURL)
                            .resultMessage("Received unknown response from external API call.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                outcome = Constants.OUTCOME_FAIL;
                statuscode = responseCode; // Other client or server error, retry if attempts left
            }
        } catch (Exception e) {
            // Log the error based on its type
            if (e instanceof IllegalArgumentException) {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                            DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            Constants.LogConstants.ActionIDs.RECEIVE_API_RESPONSE);
                    diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.EXTERNAL_API, endpointURL)
                            .resultMessage("Invalid Url for external API call.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                statuscode = HTTP_STATUS_BAD_REQUEST; // Client error, retry if attempts left
                outcome = Constants.OUTCOME_FAIL;
                LOG.error("Invalid Url: " + endpointURL, e);
            } else if (e instanceof ConnectTimeoutException) {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                            DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            Constants.LogConstants.ActionIDs.RECEIVE_API_RESPONSE);
                    diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.EXTERNAL_API, endpointURL)
                            .resultMessage("Received connection timeout from external API call.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                statuscode = HTTP_STATUS_REQUEST_TIMEOUT; // Timeout, retry if attempts left
                outcome = Constants.OUTCOME_TIMEOUT;
                LOG.error("Error while waiting to connect to " + endpointURL, e);
            } else if (e instanceof SocketTimeoutException) {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                            DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            Constants.LogConstants.ActionIDs.RECEIVE_API_RESPONSE);
                    diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.EXTERNAL_API, endpointURL)
                            .resultMessage("Received socket timeout from external API call.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                statuscode = HTTP_STATUS_REQUEST_TIMEOUT; // Timeout, retry if attempts left
                outcome = Constants.OUTCOME_TIMEOUT;
                LOG.error("Error while waiting for data from " + endpointURL, e);
            } else if (e instanceof IOException) {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                            DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            Constants.LogConstants.ActionIDs.RECEIVE_API_RESPONSE);
                    diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.EXTERNAL_API, endpointURL)
                            .resultMessage("Received IO exception from external API call.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                statuscode = HTTP_STATUS_REQUEST_TIMEOUT; // Timeout, retry if attempts left
                outcome = Constants.OUTCOME_TIMEOUT;
                LOG.error("Error while calling endpoint. ", e);
            } else if (e instanceof ParseException) {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                            DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            Constants.LogConstants.ActionIDs.RECEIVE_API_RESPONSE);
                    diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.EXTERNAL_API, endpointURL)
                            .resultMessage("Error while parsing response from external API call.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                statuscode = HTTP_STATUS_INTERNAL_SERVER_ERROR; // Server error, retry if attempts left
                outcome = Constants.OUTCOME_FAIL;
                LOG.error("Error while parsing response. ", e);
            } else {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                            DiagnosticLog.DiagnosticLogBuilder(Constants.LogConstants.ADAPTIVE_AUTH_SERVICE,
                            Constants.LogConstants.ActionIDs.RECEIVE_API_RESPONSE);
                    diagnosticLogBuilder.inputParam(Constants.LogConstants.InputKeys.EXTERNAL_API, endpointURL)
                            .resultMessage("Received unknown exception from external API call.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                statuscode = HTTP_STATUS_INTERNAL_SERVER_ERROR; // Server error, retry if attempts left
                outcome = Constants.OUTCOME_FAIL;
                LOG.error("Error while calling endpoint. ", e);
            }
        }
        // Return the outcome and json (which might be null if never successful)
        return Pair.of(statuscode, Pair.of(outcome, json));
    }

    private boolean isValidRequestDomain(URI url) {

        if (url == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Provided url for domain restriction checking is null");
            }
            return false;
        }

        if (allowedDomains.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No domains configured for domain restriction. Allowing url by default. Url: "
                        + url.toString());
            }
            return true;
        }

        String domain = getParentDomainFromUrl(url);
        if (StringUtils.isEmpty(domain)) {
            LOG.error("Unable to determine the domain of the url: " + url.toString());
            return false;
        }

        if (allowedDomains.contains(domain)) {
            return true;
        }

        LOG.error("Domain: " + domain + " extracted from url: " + url.toString() + " is not available in the " +
                "allowed domain list: " + StringUtils.join(allowedDomains, ','));

        return false;
    }

    private String getParentDomainFromUrl(URI url) {

        String parentDomain = null;
        String domain = url.getHost();
        String[] domainArr;
        if (domain != null) {
            domainArr = StringUtils.split(domain, DOMAIN_SEPARATOR);
            if (domainArr.length != 0) {
                parentDomain = domainArr.length == 1 ? domainArr[0] : domainArr[domainArr.length - 2];
                parentDomain = parentDomain.toLowerCase();
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Parent domain: " + parentDomain + " extracted from url: " + url.toString());
        }
        return parentDomain;
    }

    /**
     * Validate the headers.
     *
     * @param headers Map of headers.
     * @return Map of headers.
     */
    protected Map<String, String> validateHeaders(Map<String, ?> headers) {

        for (Map.Entry<String, ?> entry : headers.entrySet()) {
            if (!(entry.getValue() instanceof String)) {
                throw new IllegalArgumentException("Header values must be of type String");
            }
        }
        return (Map<String, String>) headers;
    }

    /**
     * Set headers to the request.
     * Default Accept header is set to application/json.
     *
     * @param request HttpUriRequest.
     * @param headers Map of headers.
     */
    protected void setHeaders(HttpUriRequest request, Map<String, String> headers) {

        headers.putIfAbsent(ACCEPT, TYPE_APPLICATION_JSON);
        headers.entrySet().stream()
                .filter(entry -> StringUtils.isNotBlank(entry.getKey()) && !entry.getKey().equals("null"))
                .forEach(entry -> request.setHeader(entry.getKey(), entry.getValue()));
    }

    /**
     * Get AuthConfigModel from the map.
     *
     * @param map Map of properties.
     * @return AuthConfigModel.
     */
    protected AuthConfigModel getAuthConfigModel(Map<String, Object> map) {
        AuthConfigModel authConfig;
        if (map.get("type") == null || map.get("properties") == null) {
            throw new IllegalArgumentException("Invalid argument type. Expected {type: string, properties: map}");
        }
        String type = (String) map.get("type");
        Map<String, Object> propertiesMap = (Map<String, Object>) map.get("properties");
        authConfig = new AuthConfigModel(type, propertiesMap);
        return authConfig;
    }
}
