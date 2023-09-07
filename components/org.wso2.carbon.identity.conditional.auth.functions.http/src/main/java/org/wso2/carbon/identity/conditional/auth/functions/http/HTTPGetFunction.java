/*
 * Copyright (c) 2018, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.conditional.auth.functions.http;

import java.util.Map;

/**
 * Function to call http endpoints. Function will send get to the given endpoint reference.
 */
@FunctionalInterface
public interface HTTPGetFunction {

    /**
     *  POST data to the given endpoint.
     *
     * @param endpointURL Endpoint url.
     * @param params Parameters.
     *      1. headers          headers (optional).
     *      2. eventHandlers    event handlers.
     */
    void httpGet(String endpointURL, Object... params);
}
