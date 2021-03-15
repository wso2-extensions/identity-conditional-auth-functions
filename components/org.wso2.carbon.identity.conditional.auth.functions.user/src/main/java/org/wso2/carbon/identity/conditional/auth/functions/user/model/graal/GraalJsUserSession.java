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

package org.wso2.carbon.identity.conditional.auth.functions.user.model.graal;

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.AbstractJSObjectWrapper;
import org.wso2.carbon.identity.application.authentication.framework.model.UserSession;
import org.wso2.carbon.identity.conditional.auth.functions.user.model.JsUserSession;
import org.wso2.carbon.identity.core.model.UserAgent;

import java.util.stream.Collectors;

/**
 * Javascript wrapper for Java level UserSession.
 * This provides controlled access to UserSession object via provided javascript native syntax.
 * Also it prevents writing an arbitrary values to the respective fields, keeping consistency on runtime
 * AuthenticatedUser.
 *
 * @see UserSession
 */
public class GraalJsUserSession extends AbstractJSObjectWrapper<UserSession> implements JsUserSession {

    private UserAgent userAgent;

    public GraalJsUserSession(UserSession wrappedUserSession) {

        super(wrappedUserSession);
        userAgent = new UserAgent(wrappedUserSession.getUserAgent());
    }

    @Override
    public Object getMember(String name) {

        switch (name) {
            case "userAgent":
                return new GraalJsUserAgent(userAgent);
            case "ip":
                return getWrapped().getIp();
            case "loginTime":
                return getWrapped().getLoginTime();
            case "lastAccessTime":
                return getWrapped().getLastAccessTime();
            case "id":
                return getWrapped().getSessionId();
            case "applications":
                return getWrapped().getApplications().stream().map(GraalJsApplication::new).collect(Collectors.toList());
            default:
                return super.getMember(name);
        }
    }

    @Override
    public boolean hasMember(String name) {

        switch (name) {
            case "userAgent":
                return true;
            case "ip":
                return getWrapped().getIp() !=null;
            case "loginTime":
                return getWrapped().getLoginTime() != null;
            case "lastAccessTime":
                return getWrapped().getLastAccessTime() !=null;
            case "id":
                return getWrapped().getSessionId() != null;
            case "applications":
                return getWrapped().getApplications() != null;
            default:
                return super.hasMember(name);

        }
    }

}
