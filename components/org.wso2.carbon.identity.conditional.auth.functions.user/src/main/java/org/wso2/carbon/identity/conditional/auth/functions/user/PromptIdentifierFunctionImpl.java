/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.conditional.auth.functions.user;

import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsGraphBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.SerializableJsFunction;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.ShowPromptNode;
import org.wso2.carbon.identity.conditional.auth.functions.user.model.JsWrapperFactoryProvider;

import java.util.HashMap;
import java.util.Map;

public class PromptIdentifierFunctionImpl implements PromptIdentifierFunction {

    public static final String DEFAULT_PRE_HANDLER_FUNC = "function(step, context) {return " +
            "checkSessionExistence(step, context);}";
    public static final String IDENTIFIER_TEMPLATE_NAME = "username";
    public static final String STEP_PARAM = "step";

    @Override
    @HostAccess.Export
    public void promptIdentifier(int step, Object... parameters) {

        Map<String, Object> validators;
        if (parameters.length == 2 && parameters[1] instanceof Map) {
            validators = (Map<String, Object>) parameters[1];
        } else {
            validators = new HashMap<>();
        }

        Map<String, Object> callbacks = null;
        if (parameters.length > 0 && parameters[parameters.length - 1] instanceof Map) {
            callbacks = (Map<String, Object>) parameters[parameters.length - 1];
        }

        if (validators.get(ShowPromptNode.PRE_HANDLER) == null) {
            validators.put(ShowPromptNode.PRE_HANDLER, JsWrapperFactoryProvider.getInstance()
                    .getWrapperFactory().createJsSerializableFunction(DEFAULT_PRE_HANDLER_FUNC, true));
        }
        Map<String, Object> promptParameters = new HashMap<>();
        promptParameters.put(STEP_PARAM, step);
        JsGraphBuilder.addPrompt(IDENTIFIER_TEMPLATE_NAME, promptParameters, validators, callbacks);
    }
}
