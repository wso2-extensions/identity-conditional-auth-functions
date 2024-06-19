/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.conditional.auth.functions.user.model.graaljs;

import org.graalvm.polyglot.Value;
import org.graalvm.polyglot.proxy.ProxyObject;
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
public class JsGraalUserSession extends JsUserSession implements ProxyObject {

    private final UserAgent userAgent;

    public JsGraalUserSession(UserSession wrappedUserSession) {

        super(wrappedUserSession);
        userAgent = new UserAgent(wrappedUserSession.getUserAgent());
    }

    @Override
    public Object getMemberKeys() {

        return new String[]{"id", "lastAccessTime", "applications", "userAgent", "ip", "loginTime"};
    }

    @Override
    public boolean hasMember(String key) {

        return "id".equals(key) || "lastAccessTime".equals(key) || "applications".equals(key) ||
                "userAgent".equals(key) || "ip".equals(key) || "loginTime".equals(key);
    }

    @Override
    public void putMember(String key, Value value) {

        // read-only object.
    }

    @Override
    public Object getMember(String name) {

        switch (name) {
            case "userAgent":
                return new JsGraalUserAgent(userAgent);
            case "ip":
                return getWrapped().getIp();
            case "loginTime":
                return getWrapped().getLoginTime();
            case "lastAccessTime":
                return getWrapped().getLastAccessTime();
            case "id":
                return getWrapped().getSessionId();
            case "applications":
                return getWrapped().getApplications().stream().map(JsGraalApplication::new)
                        .collect(Collectors.toList());
            default:
                return super.getMember(name);
        }
    }
}
