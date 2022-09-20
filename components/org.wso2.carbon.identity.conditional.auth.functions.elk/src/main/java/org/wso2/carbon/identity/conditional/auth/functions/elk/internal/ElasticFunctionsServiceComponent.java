/*
 * Copyright (c) 2022, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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
 *
 */

package org.wso2.carbon.identity.conditional.auth.functions.elk.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.identity.application.authentication.framework.JsFunctionRegistry;
import org.wso2.carbon.identity.conditional.auth.functions.elk.CallElasticFunction;
import org.wso2.carbon.identity.conditional.auth.functions.elk.CallElasticFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.elk.ElasticAnalyticsEngineConfigImpl;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * OSGi declarative services component which handle ELK related conditional auth functions.
 */
@Component(
        name = "identity.conditional.auth.functions.elk.component",
        immediate = true
)
public class ElasticFunctionsServiceComponent {

    public static final String FUNC_CALL_ELASTIC = "callElastic";
    public static final String SECURITY_TRUSTSTORE_LOCATION = "Security.TrustStore.Location";
    public static final String SECURITY_TRUSTSTORE_TYPE = "Security.TrustStore.Type";
    public static final String SECURITY_TRUSTSTORE_PASSWORD = "Security.TrustStore.Password";

    private static final Log LOG = LogFactory.getLog(ElasticFunctionsServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            JsFunctionRegistry jsFunctionRegistry = ElasticFunctionsServiceHolder.getInstance().getJsFunctionRegistry();

            CallElasticFunction callElastic = new CallElasticFunctionImpl();
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_CALL_ELASTIC, callElastic);

            BundleContext bundleContext = context.getBundleContext();
            ElasticAnalyticsEngineConfigImpl analyticsFunctionConfig = new ElasticAnalyticsEngineConfigImpl();
            bundleContext.registerService(IdentityConnectorConfig.class.getName(), analyticsFunctionConfig, null);

            ServerConfigurationService config = ElasticFunctionsServiceHolder.getInstance()
                    .getServerConfigurationService();

            String filePath = config.getFirstProperty(SECURITY_TRUSTSTORE_LOCATION);
            String keyStoreType = config.getFirstProperty(SECURITY_TRUSTSTORE_TYPE);
            String password = config.getFirstProperty(SECURITY_TRUSTSTORE_PASSWORD);
            try (InputStream keyStoreStream = Files.newInputStream(Paths.get(filePath))) {
                KeyStore keyStore = KeyStore.getInstance(keyStoreType); // or "PKCS12"
                keyStore.load(keyStoreStream, password.toCharArray());
                ElasticFunctionsServiceHolder.getInstance().setTrustStore(keyStore);
            } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
                LOG.error("Error while loading truststore.", e);
            }
        } catch (Throwable e) {
            LOG.error("Error while activating AnalyticsFunctionsServiceComponent.");
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        JsFunctionRegistry jsFunctionRegistry = ElasticFunctionsServiceHolder.getInstance().getJsFunctionRegistry();
        if (jsFunctionRegistry != null) {
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_CALL_ELASTIC);
        }
    }

    @Reference(
            service = JsFunctionRegistry.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetJsFunctionRegistry"
    )
    public void setJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        ElasticFunctionsServiceHolder.getInstance().setJsFunctionRegistry(jsFunctionRegistry);
    }

    public void unsetJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        ElasticFunctionsServiceHolder.getInstance().setJsFunctionRegistry(null);
    }

    @Reference(
            name = "identityCoreInitializedEventService",
            service = IdentityCoreInitializedEvent.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityCoreInitializedEventService")
    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {

    /* Reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started. */
    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {

    /* Reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started. */
    }

    @Reference(
            name = "identity.governance.service",
            service = IdentityGovernanceService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityGovernanceService"
    )
    protected void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Identity Governance service is set form functions.");
        }
        // Do nothing. Wait for the service before registering the governance connector.
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Identity Governance service is unset from functions.");
        }
        // Do nothing.
    }

    @Reference(
            name = "server.configuration.service",
            service = ServerConfigurationService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetServerConfigurationService"
    )
    protected void setServerConfigurationService(ServerConfigurationService serverConfigurationService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Setting the serverConfigurationService.");
        }
        ElasticFunctionsServiceHolder.getInstance().setServerConfigurationService(serverConfigurationService);
    }

    protected void unsetServerConfigurationService(ServerConfigurationService serverConfigurationService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Unsetting the ServerConfigurationService.");
        }
        ElasticFunctionsServiceHolder.getInstance().setServerConfigurationService(null);
    }
}
