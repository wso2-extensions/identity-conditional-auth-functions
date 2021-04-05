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

package org.wso2.carbon.identity.conditional.auth.functions.user.model.nashorn;

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.AbstractJSObjectWrapper;
import org.wso2.carbon.identity.application.authentication.framework.model.Application;
import org.wso2.carbon.identity.conditional.auth.functions.user.model.JsApplication;

/**
 * Javascript wrapper for Java level Application.
 * This provides controlled access to UserSession object via provided javascript native syntax.
 * Also it prevents writing an arbitrary values to the respective fields, keeping consistency on runtime
 * AuthenticatedUser.
 *
 * @see Application
 */
public class NashornJsApplication extends AbstractJSObjectWrapper<Application> implements JsApplication {

    public NashornJsApplication(Application wrappedApplication) {

        super(wrappedApplication);
    }

    @Override
    public Object getMember(String name) {

        switch (name) {
            case "subject":
                return getWrapped().getSubject();
            case "appName":
                return getWrapped().getAppName();
            case "appId":
                return getWrapped().getAppId();
            default:
                return super.getMember(name);
        }
    }
}
