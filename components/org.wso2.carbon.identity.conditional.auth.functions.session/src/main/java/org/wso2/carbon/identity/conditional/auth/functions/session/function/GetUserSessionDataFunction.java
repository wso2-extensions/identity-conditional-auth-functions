/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */
package org.wso2.carbon.identity.conditional.auth.functions.session.function;

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.conditional.auth.functions.session.model.Session;

import java.util.Map;

/**
 * Function definition for retrieving data.
 *
 * @deprecated
 */
@FunctionalInterface
@Deprecated
public interface GetUserSessionDataFunction {

    /**
     * This function will contain the implementation for retrieving data.
     *
     * @param context AuthenticationContext object passed from Javascript
     * @param map     parameter map
     * @return Map of sessionID and sessions
     * @throws FrameworkException
     */
    Map<String, Session> getData(JsAuthenticationContext context, Map<String, String> map) throws
            FrameworkException;
}
