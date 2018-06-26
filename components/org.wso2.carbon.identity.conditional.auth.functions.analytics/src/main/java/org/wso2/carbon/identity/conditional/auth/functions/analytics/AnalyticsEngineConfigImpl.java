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

package org.wso2.carbon.identity.conditional.auth.functions.analytics;

import org.wso2.carbon.identity.conditional.auth.functions.common.utils.ConfigProvider;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * Governance connector used to configure the parameters need invoke the analytics engine.
 */
public class AnalyticsEngineConfigImpl implements IdentityConnectorConfig {

    public static final String RECEIVER = "adaptive_authentication.analytics.receiver";
    public static final String BASIC_AUTH_ENABLED = "adaptive_authentication.analytics.basicAuth.enabled";
    public static final String USERNAME = "adaptive_authentication.analytics.basicAuth.username";
    public static final String PASSWORD = "__secret__adaptive_authentication.analytics.basicAuth.password";
    public static final String HTTPCONNECTION_TIMEOUT = "adaptive_authentication.analytics.HTTPConnectionTimeout";
    public static final String HTTPREAD_TIMEOUT = "adaptive_authentication.analytics.HTTPReadTimeout";
    public static final String HTTPCONNECTION_REQUEST_TIMEOUT = "adaptive_authentication.analytics" +
            ".HTTPConnectionRequestTimeout";
    public static final String HOSTNAME_VERIFIER = "adaptive_authentication.analytics.hostnameVerfier";

    public static final String DEFAULT_TARGET_HOST = "http://localhost:8280/";
    public static final String DEFAULT_AUTHENTICATION_ENABLED = "true";
    public static final String DEFAULT_USERNAME = "change-me";
    public static final String DEFAULT_PASSWORD = "change-me";
    public static final String HOSTNAME_VERIFIER_STRICT = "STRICT";
    public static final String HOSTNAME_VERIFIER_ALLOW_ALL = "ALLOW_ALL";
    public static final String DEFAULT_HOSTNAME_VERIFIER = HOSTNAME_VERIFIER_STRICT;

    @Override
    public String getName() {

        return "analytics-engine";
    }

    @Override
    public String getFriendlyName() {

        return "Analytics Engine";
    }

    @Override
    public String getCategory() {

        return "Adaptive Authentication";
    }

    @Override
    public String getSubCategory() {

        return "DEFAULT";
    }

    @Override
    public int getOrder() {

        return 10;
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {

        Map<String, String> mapping = new HashMap<>();

        mapping.put(RECEIVER, "Target Host");
        mapping.put(BASIC_AUTH_ENABLED, "Enable Basic Authentication");
        mapping.put(USERNAME, "User ID");
        mapping.put(PASSWORD, "Secret");
        mapping.put(HTTPCONNECTION_TIMEOUT, "HTTP Connection Timeout");
        mapping.put(HTTPREAD_TIMEOUT, "HTTP Read Timeout");
        mapping.put(HTTPCONNECTION_REQUEST_TIMEOUT, "HTTP Connection Request Timeout");
        mapping.put(HOSTNAME_VERIFIER, "Hostname verifier");

        return mapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {

        Map<String, String> mapping = new HashMap<>();

        mapping.put(RECEIVER, "Target Host");
        mapping.put(BASIC_AUTH_ENABLED, "Enable Basic Authentication");
        mapping.put(USERNAME, "Target Host Secured User ID");
        mapping.put(PASSWORD, "Target Host Secured Secret");
        mapping.put(HTTPCONNECTION_TIMEOUT, "HTTP Connection Timeout in milliseconds");
        mapping.put(HTTPREAD_TIMEOUT, "HTTP Read Timeout in milliseconds");
        mapping.put(HTTPCONNECTION_REQUEST_TIMEOUT, "HTTP Connection Request Timeout in milliseconds");
        mapping.put(HOSTNAME_VERIFIER, "Hostname verifier. (STRICT, ALLOW_ALL)");

        return mapping;
    }

    @Override
    public String[] getPropertyNames() {

        List<String> properties = new ArrayList<>();
        properties.add(RECEIVER);
        properties.add(BASIC_AUTH_ENABLED);
        properties.add(USERNAME);
        properties.add(PASSWORD);
        properties.add(HTTPCONNECTION_TIMEOUT);
        properties.add(HTTPREAD_TIMEOUT);
        properties.add(HTTPCONNECTION_REQUEST_TIMEOUT);
        properties.add(HOSTNAME_VERIFIER);
        return properties.toArray(new String[0]);
    }

    @Override
    public Properties getDefaultPropertyValues(String s) throws IdentityGovernanceException {

        Map<String, String> defaultProperties = new HashMap<>();

        String targetHost = IdentityUtil.getProperty(Constants.RECEIVER_URL);
        defaultProperties.put(RECEIVER, targetHost != null ? targetHost : DEFAULT_TARGET_HOST);
        String basicAuthEnable = IdentityUtil.getProperty(Constants.AUTHENTICATION_ENABLED);
        defaultProperties.put(BASIC_AUTH_ENABLED, basicAuthEnable != null ? basicAuthEnable :
                DEFAULT_AUTHENTICATION_ENABLED);
        String username = IdentityUtil.getProperty(Constants.AUTHENTICATION_USERNAME);
        defaultProperties.put(USERNAME, username != null ? username : DEFAULT_USERNAME);
        String password = IdentityUtil.getProperty(Constants.AUTHENTICATION_PASSWORD);
        defaultProperties.put(PASSWORD, password != null ? password : DEFAULT_PASSWORD);
        defaultProperties.put(HTTPCONNECTION_TIMEOUT, String.valueOf(ConfigProvider.getInstance()
                .getConnectionTimeout()));
        defaultProperties.put(HTTPREAD_TIMEOUT, String.valueOf(ConfigProvider.getInstance()
                .getReadTimeout()));
        defaultProperties.put(HTTPCONNECTION_REQUEST_TIMEOUT, String.valueOf(ConfigProvider.getInstance()
                .getConnectionRequestTimeout()));
        String hostnameVerifier = IdentityUtil.getProperty(Constants.HOSTNAME_VERIFIER);
        if (!HOSTNAME_VERIFIER_STRICT.equalsIgnoreCase(hostnameVerifier)
                && !HOSTNAME_VERIFIER_ALLOW_ALL.equalsIgnoreCase(hostnameVerifier)) {
            hostnameVerifier = DEFAULT_HOSTNAME_VERIFIER;
        }
        defaultProperties.put(HOSTNAME_VERIFIER, hostnameVerifier);

        Properties properties = new Properties();
        properties.putAll(defaultProperties);
        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] strings, String s) throws IdentityGovernanceException {

        return null;
    }
}
