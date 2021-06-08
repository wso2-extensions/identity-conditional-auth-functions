package org.wso2.carbon.identity.conditional.auth.functions.choreo;

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

public class ChoreoConfigImpl implements IdentityConnectorConfig {

    public static final String RECEIVER = "adaptive_authentication.choreo.receiver";
    public static final String BASIC_AUTH_ENABLED = "adaptive_authentication.choreo.basicAuth.enabled";
    public static final String USERNAME = "adaptive_authentication.choreo.basicAuth.username";
    public static final String CREDENTIAL = "__secret__adaptive_authentication.choreo.basicAuth.password";
    public static final String HTTP_CONNECTION_TIMEOUT = "adaptive_authentication.choreo.HTTPConnectionTimeout";
    public static final String HTTP_READ_TIMEOUT = "adaptive_authentication.choreo.HTTPReadTimeout";
    public static final String HTTP_CONNECTION_REQUEST_TIMEOUT = "adaptive_authentication.choreo" +
            ".HTTPConnectionRequestTimeout";
    public static final String HOSTNAME_VERIFIER = "adaptive_authentication.choreo.hostnameVerfier";

    public static final String DEFAULT_TARGET_HOST = "https://riskcalculation-chanikaruchini-test.choreo.dev/";
    public static final String DEFAULT_AUTHENTICATION_ENABLED = "true";
    public static final String DEFAULT_USERNAME = "change-me";
    public static final String DEFAULT_CREDENTIAL = "change-me";
    public static final String HOSTNAME_VERIFIER_STRICT = "STRICT";
    public static final String HOSTNAME_VERIFIER_ALLOW_ALL = "ALLOW_ALL";
    public static final String DEFAULT_HOSTNAME_VERIFIER = HOSTNAME_VERIFIER_STRICT;

    @Override
    public String getName() {

        return "Choreo";
    }

    @Override
    public String getFriendlyName() {

        return "Choreo Configuration";
    }

    @Override
    public String getCategory() {

        return "Other Settings";
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
        mapping.put(CREDENTIAL, "Secret");
        mapping.put(HTTP_CONNECTION_TIMEOUT, "HTTP Connection Timeout");
        mapping.put(HTTP_READ_TIMEOUT, "HTTP Read Timeout");
        mapping.put(HTTP_CONNECTION_REQUEST_TIMEOUT, "HTTP Connection Request Timeout");
        mapping.put(HOSTNAME_VERIFIER, "Hostname verification");

        return mapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {

        Map<String, String> mapping = new HashMap<>();

        mapping.put(RECEIVER, "Target Host");
        mapping.put(BASIC_AUTH_ENABLED, "Enable Basic Authentication");
        mapping.put(USERNAME, "Target Host Secured User ID");
        mapping.put(CREDENTIAL, "Target Host Secured Secret");
        mapping.put(HTTP_CONNECTION_TIMEOUT, "HTTP Connection Timeout in milliseconds");
        mapping.put(HTTP_READ_TIMEOUT, "HTTP Read Timeout in milliseconds");
        mapping.put(HTTP_CONNECTION_REQUEST_TIMEOUT, "HTTP Connection Request Timeout in milliseconds");
        mapping.put(HOSTNAME_VERIFIER, "Hostname verification. (STRICT, ALLOW_ALL)");

        return mapping;
    }

    @Override
    public String[] getPropertyNames() {

        List<String> properties = new ArrayList<>();
        properties.add(RECEIVER);
        properties.add(BASIC_AUTH_ENABLED);
        properties.add(USERNAME);
        properties.add(CREDENTIAL);
        properties.add(HTTP_CONNECTION_TIMEOUT);
        properties.add(HTTP_READ_TIMEOUT);
        properties.add(HTTP_CONNECTION_REQUEST_TIMEOUT);
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
        String password = IdentityUtil.getProperty(Constants.AUTHENTICATION_CREDENTIAL);
        defaultProperties.put(CREDENTIAL, password != null ? password : DEFAULT_CREDENTIAL);
        defaultProperties.put(HTTP_CONNECTION_TIMEOUT, String.valueOf(ConfigProvider.getInstance()
                .getConnectionTimeout()));
        defaultProperties.put(HTTP_READ_TIMEOUT, String.valueOf(ConfigProvider.getInstance()
                .getReadTimeout()));
        defaultProperties.put(HTTP_CONNECTION_REQUEST_TIMEOUT, String.valueOf(ConfigProvider.getInstance()
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
    public Map<String, String> getDefaultPropertyValues(String[] strings, String s)
            throws IdentityGovernanceException {

        return null;
    }

}
