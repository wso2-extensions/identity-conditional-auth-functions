package org.wso2.carbon.identity.conditional.auth.functions.choreo;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.methods.HttpPost;
import org.wso2.carbon.identity.conditional.auth.functions.common.auth.AuthenticationFactory;
import org.wso2.carbon.identity.conditional.auth.functions.common.auth.AuthenticationManager;
import org.wso2.carbon.identity.conditional.auth.functions.common.auth.UsernamePasswordCredentials;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.CommonUtils;
import org.wso2.carbon.identity.event.IdentityEventException;

public class AbstractChoreoFunction {

    private static final Log LOG = LogFactory.getLog(AbstractChoreoFunction.class);

    protected AuthenticationFactory authenticationFactory = new AuthenticationFactory();

    /**
     * Handle the authentication of the external calls with Choreo.
     *
     * @param request      Request sent to the Choreo.
     * @param tenantDomain tenant domain of the service provider.
     * @throws IdentityEventException
     */
    protected void handleAuthentication(HttpPost request, String tenantDomain) throws IdentityEventException {

        if (Boolean.parseBoolean(isBasicAuthEnabled(tenantDomain))) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Basic Authentication enabled for outbound Choreo calls in the tenant:" + tenantDomain);
            }
            String username = getUsername(tenantDomain);
            String password = getPassword(tenantDomain);

            AuthenticationManager authenticationManager = authenticationFactory.getAuthenticationManager("Basic");
            request.setHeader(authenticationManager.authenticate(new UsernamePasswordCredentials(username,
                    password), request));
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Basic Authentication is not enabled for outbound Choreo calls in for the tenant:" +
                        tenantDomain);
            }
        }
    }

    protected String getPassword(String tenantDomain) throws IdentityEventException {

        return CommonUtils.getConnectorConfig(ChoreoConfigImpl.CREDENTIAL, tenantDomain);
    }

    protected String getUsername(String tenantDomain) throws IdentityEventException {

        return CommonUtils.getConnectorConfig(ChoreoConfigImpl.USERNAME, tenantDomain);
    }

    protected String isBasicAuthEnabled(String tenantDomain) throws IdentityEventException {

        return CommonUtils.getConnectorConfig(ChoreoConfigImpl.BASIC_AUTH_ENABLED, tenantDomain);
    }

}
