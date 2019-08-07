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
            case "userAgent":
                return getWrapped().getUserAgent();
            case "ip":
                return getWrapped().getIp();
            case "loginTime":
                return getWrapped().getLoginTime();
            case "lastAccessTime":
                return getWrapped().getLastAccessTime();
            case "id":
                return getWrapped().getSessionId();
            default:
                return super.getMember(name);
        }
    }

}
