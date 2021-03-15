package org.wso2.carbon.identity.conditional.auth.functions.user.model;

import org.wso2.carbon.identity.application.authentication.framework.model.UserSession;

public interface JsUserSession {
    UserSession getWrapped();
}
