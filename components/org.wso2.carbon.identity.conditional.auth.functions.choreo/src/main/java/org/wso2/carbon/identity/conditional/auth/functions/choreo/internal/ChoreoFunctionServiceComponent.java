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

package org.wso2.carbon.identity.conditional.auth.functions.choreo.internal;

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
import org.wso2.carbon.identity.conditional.auth.functions.choreo.CallChoreoFunction;
import org.wso2.carbon.identity.conditional.auth.functions.choreo.CallChoreoFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.choreo.ChoreoConfigImpl;
import org.wso2.carbon.identity.conditional.auth.functions.choreo.listener.ChoreoAxis2ConfigurationContextObserver;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.utils.Axis2ConfigurationContextObserver;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * OSGi declarative services component which handled registration and un-registration of choreo requests related
 * functions.
 */

@Component(
        name = "identity.conditional.auth.functions.choreo.component",
        immediate = true
)
public class ChoreoFunctionServiceComponent {

    public static final String FUNC_CALL_CHOREO = "callChoreo";
    private static final Log LOG = LogFactory.getLog(ChoreoFunctionServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        JsFunctionRegistry jsFunctionRegistry = ChoreoFunctionServiceHolder.getInstance().getJsFunctionRegistry();

        CallChoreoFunction callChoreo = new CallChoreoFunctionImpl();
        jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_CALL_CHOREO, callChoreo);

        BundleContext bundleContext = context.getBundleContext();
        ChoreoConfigImpl choreoConfig = new ChoreoConfigImpl();
        bundleContext.registerService(IdentityConnectorConfig.class.getName(), choreoConfig, null);

        ChoreoAxis2ConfigurationContextObserver observer = new ChoreoAxis2ConfigurationContextObserver();
        bundleContext.registerService(Axis2ConfigurationContextObserver.class.getName(), observer, null);
        ServerConfigurationService config = ChoreoFunctionServiceHolder.getInstance()
                .getServerConfigurationService();

        String filePath = config.getFirstProperty("Security.TrustStore.Location");
        String keyStoreType = config.getFirstProperty("Security.TrustStore.Type");
        String password = config.getFirstProperty("Security.TrustStore.Password");
        try (InputStream keyStoreStream = new FileInputStream(filePath)) {
            KeyStore keyStore = KeyStore.getInstance(keyStoreType); // or "PKCS12"
            keyStore.load(keyStoreStream, password.toCharArray());
            ChoreoFunctionServiceHolder.getInstance().setTrustStore(keyStore);
        } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
            LOG.error("Error while loading truststore.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        JsFunctionRegistry jsFunctionRegistry = ChoreoFunctionServiceHolder.getInstance().getJsFunctionRegistry();
        if (jsFunctionRegistry != null) {
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_CALL_CHOREO);
        }
    }

    @Reference(
            service = JsFunctionRegistry.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetJsFunctionRegistry"
    )
    public void setJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        ChoreoFunctionServiceHolder.getInstance().setJsFunctionRegistry(jsFunctionRegistry);
    }

    public void unsetJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        ChoreoFunctionServiceHolder.getInstance().setJsFunctionRegistry(null);
    }

    @Reference(
            name = "identityCoreInitializedEventService",
            service = IdentityCoreInitializedEvent.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityCoreInitializedEventService")
    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {

    /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {

    /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
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
            LOG.debug("Setting the serverConfigurationService");
        }
        ChoreoFunctionServiceHolder.getInstance().setServerConfigurationService(serverConfigurationService);
    }

    protected void unsetServerConfigurationService(ServerConfigurationService serverConfigurationService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Unsetting the ServerConfigurationService");
        }
        ChoreoFunctionServiceHolder.getInstance().setServerConfigurationService(null);
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
            LOG.debug("Identity Governance service is set form functions");
        }
        // Do nothing. Wait for the service before registering the governance connector.
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Identity Governance service is unset from functions");
        }
        // Do nothing.
    }
}
