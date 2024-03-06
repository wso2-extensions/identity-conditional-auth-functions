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

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.openjdk.nashorn.OpenJdkNashornSerializableJsFunction;
import org.wso2.carbon.identity.application.authentication.framework.model.Application;
import org.wso2.carbon.identity.application.authentication.framework.model.UserSession;
import org.wso2.carbon.identity.conditional.auth.functions.user.model.openjdk.nashorn.JsOpenJdkNashornApplication;
import org.wso2.carbon.identity.conditional.auth.functions.user.model.openjdk.nashorn.JsOpenJdkNashornUserSession;

/**
 * Factory to create a Javascript Object Wrappers for OpenJDk.Nashorn execution.
 * Since Nashorn is deprecated in JDK 11 and onwards. We are introducing OpenJDK Nashorn engine.
 */
public class JsOpenJdkNashornWrapperFactory implements JsWrapperBaseFactory {

    @Override
    public JsUserSession createJsUserSession(UserSession userSession) {

        return new JsOpenJdkNashornUserSession(userSession);
    }

    @Override
    public JsApplication createJsApplication(Application application) {

        return new JsOpenJdkNashornApplication(application);
    }

    public OpenJdkNashornSerializableJsFunction createJsSerializableFunction(String source, boolean isFunction) {

        return new OpenJdkNashornSerializableJsFunction(source, isFunction);
    }
}
