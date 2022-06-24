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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.ConfigProvider;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Abstract class for handling http calls.
 */
public abstract class AbstractHTTPFunction {

    private static final Log LOG = LogFactory.getLog(AbstractHTTPFunction.class);
    protected static final String TYPE_APPLICATION_JSON = "application/json";
    protected static final String TYPE_APPLICATION_FORM_URLENCODED = "application/x-www-form-urlencoded";
    private static final char DOMAIN_SEPARATOR = '.';
    private final List<String> allowedDomains;

    private CloseableHttpClient client;

    public AbstractHTTPFunction() {

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

    protected void executeHttpMethod(HttpUriRequest request, Map<String, Object> eventHandlers) {

        AsyncProcess asyncProcess = new AsyncProcess((context, asyncReturn) -> {
            JSONObject json = null;
            int responseCode;
            String outcome;
            String epUrl = null;

            if (request.getURI() != null) {
                epUrl = request.getURI().toString();
            }

            if (!isValidRequestDomain(request.getURI())) {
                outcome = Constants.OUTCOME_FAIL;
                LOG.error("Provided Url does not contain a allowed domain. Invalid Url: " + epUrl);
                asyncReturn.accept(context, Collections.emptyMap(), outcome);
                return;
            }

            try (CloseableHttpResponse response = client.execute(request)) {
                responseCode = response.getStatusLine().getStatusCode();
                if (responseCode >= 200 && responseCode < 300) {
                    outcome = Constants.OUTCOME_SUCCESS;
                    String jsonString = EntityUtils.toString(response.getEntity());
                    JSONParser parser = new JSONParser();
                    json = (JSONObject) parser.parse(jsonString);
                } else {
                    outcome = Constants.OUTCOME_FAIL;
                }

            } catch (IllegalArgumentException e) {
                LOG.error("Invalid Url: " + epUrl, e);
                outcome = Constants.OUTCOME_FAIL;
            } catch (ConnectTimeoutException e) {
                LOG.error("Error while waiting to connect to " + epUrl, e);
                outcome = Constants.OUTCOME_TIMEOUT;
            } catch (SocketTimeoutException e) {
                LOG.error("Error while waiting for data from " + epUrl, e);
                outcome = Constants.OUTCOME_TIMEOUT;
            } catch (IOException e) {
                LOG.error("Error while calling endpoint. ", e);
                outcome = Constants.OUTCOME_FAIL;
            } catch (ParseException e) {
                LOG.error("Error while parsing response. ", e);
                outcome = Constants.OUTCOME_FAIL;
            }

            asyncReturn.accept(context, json != null ? json : Collections.emptyMap(), outcome);
        });
        JsGraphBuilder.addLongWaitProcess(asyncProcess, eventHandlers);
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

        if (LOG.isDebugEnabled()) {
            LOG.debug("Domain: " + domain + " extracted from url: " + url.toString() + " is not available in the " +
                    "allowed domain list: " + StringUtils.join(allowedDomains, ','));
        }

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
}
