/*
 * Copyright (c) 2022, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.conditional.auth.functions.user.model;

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.SerializableJsFunction;
import org.wso2.carbon.identity.application.authentication.framework.model.Application;
import org.wso2.carbon.identity.application.authentication.framework.model.UserSession;
import org.wso2.carbon.identity.conditional.auth.functions.user.model.nashorn.JsNashornApplication;
import org.wso2.carbon.identity.conditional.auth.functions.user.model.nashorn.JsNashornUserSession;

/**
 * Factory to create a Javascript Object Wrappers for Nashorn execution.
 */
public class JsWrapperFactory implements JsWrapperBaseFactory {

    @Override
    public JsUserSession createJsUserSession(UserSession userSession) {
        return new JsNashornUserSession(userSession);
    }

    public JsApplication createJsApplication(Application application) {
        return new JsNashornApplication(application);
    }

    public SerializableJsFunction createJsSerializableFunction(String source, boolean isFunction) {

        return new SerializableJsFunction(source, isFunction);
    }
}
