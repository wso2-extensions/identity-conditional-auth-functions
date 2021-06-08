package org.wso2.carbon.identity.conditional.auth.functions.choreo.listener;

import org.apache.axis2.context.ConfigurationContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.conditional.auth.functions.choreo.ClientManager;
import org.wso2.carbon.utils.AbstractAxis2ConfigurationContextObserver;

import java.io.IOException;

public class ChoreoAxis2ConfigurationContextObserver extends AbstractAxis2ConfigurationContextObserver {

    private static final Log log = LogFactory.getLog(
            ChoreoAxis2ConfigurationContextObserver.class);

    public void terminatingConfigurationContext(ConfigurationContext configContext) {

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            ClientManager.getInstance().closeClient(tenantId);
        } catch (IOException e) {
            log.error("Error while closing http client for tenant: " + tenantId, e);
        }
    }
}


