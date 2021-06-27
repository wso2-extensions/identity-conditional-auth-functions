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

package org.wso2.carbon.identity.conditional.auth.functions.choreo.listener;

import org.apache.axis2.context.ConfigurationContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.conditional.auth.functions.choreo.internal.ChoreoFunctionServiceHolder;
import org.wso2.carbon.utils.AbstractAxis2ConfigurationContextObserver;

import java.io.IOException;

/**
 * This class is responsible for closing the http client used for the tenant when the tenant is unloaded.
 */
public class ChoreoAxis2ConfigurationContextObserver extends AbstractAxis2ConfigurationContextObserver {

    private static final Log LOG = LogFactory.getLog(
            ChoreoAxis2ConfigurationContextObserver.class);

    public void terminatingConfigurationContext(ConfigurationContext configContext) {

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            ChoreoFunctionServiceHolder.getInstance().getClientManager().closeClient(tenantId);
        } catch (IOException e) {
            LOG.error("Error while closing http client for tenant: " + tenantId, e);
        }
    }
}
