/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.wso2.carbon.identity.conditional.auth.functions.user.model.JsUserAgent;
import org.wso2.carbon.identity.core.model.UserAgent;

/**
 * Javascript wrapper for Java level UserAgent.
 * This provides controlled access to UserSession object via provided javascript native syntax.
 * Also it prevents writing an arbitrary values to the respective fields, keeping consistency on runtime
 * AuthenticatedUser.
 *
 * @see UserAgent
 */
public class GraalJsUserAgent extends AbstractJSObjectWrapper<UserAgent> implements JsUserAgent {

    public GraalJsUserAgent(UserAgent wrappedUserAgent) {

        super(wrappedUserAgent);
    }

    @Override
    public Object getMember(String name) {

        switch (name) {
            case "rawString":
                return getWrapped().getRawString();
            case "browser":
                return getWrapped().getBrowser();
            case "platform":
                return getWrapped().getPlatform();
            case "device":
                return getWrapped().getDevice();
            default:
                return super.getMember(name);
        }
    }

    @Override
    public boolean hasMember(String name) {
        switch (name) {
            case "rawString":
                return getWrapped().getRawString() != null;
            case "browser":
                return getWrapped().getBrowser() !=null;
            case "platform":
                return getWrapped().getPlatform() !=null;
            case "device":
                return getWrapped().getDevice() !=null;
            default:
                return super.hasMember(name);
        }
    }
}
