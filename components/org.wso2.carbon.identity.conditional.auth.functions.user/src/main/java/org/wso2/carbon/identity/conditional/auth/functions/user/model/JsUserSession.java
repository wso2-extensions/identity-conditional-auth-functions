/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.conditional.auth.functions.user.model;

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.AbstractJSObjectWrapper;
import org.wso2.carbon.identity.application.authentication.framework.model.UserSession;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;

/**
 * Javascript wrapper for Java level UserSession.
 * This provides controlled access to UserSession object via provided javascript native syntax.
 * Also it prevents writing an arbitrary values to the respective fields, keeping consistency on runtime
 * AuthenticatedUser.
 *
 * @see UserSession
 */
public class JsUserSession extends AbstractJSObjectWrapper<UserSession> {

    public JsUserSession(UserSession wrappedUserSession) {
        super(wrappedUserSession);
    }

    @Override
    public Object getMember(String name) {

        switch (name) {
            case FrameworkConstants.JSAttributes.JS_USER_AGENT:
                return getWrapped().getUserAgent();
            case FrameworkConstants.JSAttributes.JS_IP_ADDRESS:
                return getWrapped().getIp();
            case FrameworkConstants.JSAttributes.JS_LOGIN_TIME:
                return getWrapped().getLoginTime();
            case FrameworkConstants.JSAttributes.JS_LAST_ACCESS_TIME:
                return getWrapped().getLastAccessTime();
            case FrameworkConstants.JSAttributes.JS_SESSION_ID:
                return getWrapped().getSessionId();
            default:
                return super.getMember(name);
        }
    }

}
