/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.conditional.auth.functions.opa;

import java.util.Map;

/**
 * Function to call OPA endpoints. Function will post to the given OPA endpoint reference with input data as a json.
 */
@FunctionalInterface
public interface InvokeOpaFunction {
    /**
     * POST data to the given endpoint.
     *
     * @param epUrl         Endpoint url.
     * @param payload       context and other data.
     * @param options       the kind of authentication.
     * @param eventHandlers event handlers.
     */
    void invokeOPA(String epUrl, Map<String, Object> payload, Map<String, String> options, Map<String, Object> eventHandlers);
}
