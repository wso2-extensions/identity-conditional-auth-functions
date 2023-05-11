package org.wso2.carbon.identity.conditional.auth.functions.user;

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;

@FunctionalInterface
public interface CheckVerifiedEmailFunction {

    boolean checkVerifiedEmail(JsAuthenticationContext context);
}
