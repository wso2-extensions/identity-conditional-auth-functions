package org.wso2.carbon.identity.conditional.auth.functions.user;

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;

import java.util.List;

@FunctionalInterface
public interface GetUserSessionsFunction {
    List<String> getUserSessions(JsAuthenticatedUser user);
}
