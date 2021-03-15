package org.wso2.carbon.identity.conditional.auth.functions.acr;

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;

@FunctionalInterface
public interface SelectOneFunction {
    String evaluate(JsAuthenticationContext context, Object... PossibleOutcomesObj);
}
