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

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.GenericSerializableJsFunction;
import org.wso2.carbon.identity.application.authentication.framework.model.Application;
import org.wso2.carbon.identity.application.authentication.framework.model.UserSession;

/**
 * Interface to create Js Wrapper objects.
 */
public interface JsWrapperBaseFactory {

    /**
     * Creates a JavaScript Proxy for User session.
     * @param userSession - Represent User session Subject
     * @return Proxy for User Session
     */
    JsUserSession createJsUserSession(UserSession userSession);

    /**
     * Creates a JavaScript Proxy for Application.
     * @param application - Represent Application Subject
     * @return Proxy for Application
     */
    JsApplication createJsApplication(Application application);

    /**
     * Creates a Serializable Javascript function.
     *
     * @param source     - Source of the function
     * @param isFunction - Is the source a function
     * @return Serializable Javascript function
     */
    GenericSerializableJsFunction createJsSerializableFunction(String source, boolean isFunction);
}
