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

package org.wso2.carbon.identity.conditional.auth.functions.common.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.secret.mgt.core.SecretResolveManager;

@Component(
        name = "identity.conditional.auth.functions.common",
        immediate = true
)
public class FunctionsServiceComponent {

    private static final Log LOG = LogFactory.getLog(FunctionsServiceComponent.class);

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
        FunctionsDataHolder.getInstance().setIdentityGovernanceService(identityGovernanceService);
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Identity Governance service is unset from functions");
        }
        FunctionsDataHolder.getInstance().setIdentityGovernanceService(null);
    }

    @Reference(
            name = "secret.config.manager",
            service = SecretResolveManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetSecretConfigManager"
    )
    protected void setSecretConfigManager(SecretResolveManager secretConfigManager) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Secret Config Manager is set form functions");
        }
        FunctionsDataHolder.getInstance().setSecretConfigManager(secretConfigManager);
    }

    protected void unsetSecretConfigManager(SecretResolveManager secretConfigManager) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Secret Config Manager is unset from functions");
        }
        FunctionsDataHolder.getInstance().setSecretConfigManager(null);
    }
}
