package org.wso2.carbon.identity.conditional.auth.functions.user;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserSessionException;
import org.wso2.carbon.identity.application.authentication.framework.exception.session.mgt.SessionManagementException;
import org.wso2.carbon.identity.application.authentication.framework.store.UserSessionStore;
import org.wso2.carbon.identity.conditional.auth.functions.user.internal.UserFunctionsServiceHolder;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;

public class KillAllUserSessionsImpl implements KillAllUserSessions {

    private static final Log LOG = LogFactory.getLog(KillAllUserSessions.class);

    @Override
    public boolean killUserSessions(JsAuthenticatedUser user) {
        boolean result = false;
        String tenantDomain = user.getWrapped().getTenantDomain();
        String userStoreDomain = user.getWrapped().getUserStoreDomain();
        String username = user.getWrapped().getUserName();

        try {
            UserRealm userRealm = Utils.getUserRealm(user.getWrapped().getTenantDomain());
            if (userRealm != null) {
                UserStoreManager userStore = Utils.getUserStoreManager(tenantDomain, userRealm, userStoreDomain);
                if (userStore != null) {
                    String userId = UserSessionStore.getInstance().getUserId(username, Utils.getTenantId(tenantDomain), userStoreDomain);
                    result = UserFunctionsServiceHolder.getInstance().getUserSessionManagementService().terminateSessionsByUserId(userId);
                }
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("All active sessions killed for user: " + username);
            }
        } catch (SessionManagementException e) {
            LOG.error("Error occurred while killing sessions: ", e);
        } catch (FrameworkException e) {
            LOG.error("Error in evaluating the function ", e);
        } catch (UserSessionException e) {
            LOG.error("Error occurred while retrieving the UserID: ", e);
        } finally {
            return result;
        }
    }
}
