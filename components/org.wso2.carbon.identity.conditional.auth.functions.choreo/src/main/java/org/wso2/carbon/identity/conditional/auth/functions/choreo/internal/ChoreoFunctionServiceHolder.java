package org.wso2.carbon.identity.conditional.auth.functions.choreo.internal;

import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.identity.application.authentication.framework.JsFunctionRegistry;

import java.security.KeyStore;

public class ChoreoFunctionServiceHolder {

    private static ChoreoFunctionServiceHolder instance = new ChoreoFunctionServiceHolder();

    private JsFunctionRegistry jsFunctionRegistry;
    private ServerConfigurationService serverConfigurationService;
    private KeyStore trustStore;

    public KeyStore getTrustStore() {

        return trustStore;
    }

    public void setTrustStore(KeyStore trustStore) {

        this.trustStore = trustStore;
    }

    public ServerConfigurationService getServerConfigurationService() {

        return serverConfigurationService;
    }

    public void setServerConfigurationService(ServerConfigurationService serverConfigurationService) {

        this.serverConfigurationService = serverConfigurationService;
    }

    public static ChoreoFunctionServiceHolder getInstance() {

        return instance;
    }

    public JsFunctionRegistry getJsFunctionRegistry() {

        return jsFunctionRegistry;
    }

    public void setJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        this.jsFunctionRegistry = jsFunctionRegistry;
    }

}
