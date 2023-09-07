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
import java.util.function.Consumer;

/**
 * Function to call http endpoints. Function will post to the given endpoint reference with payload data as a json.
 */
@FunctionalInterface
public interface HTTPPostFunction {

    /**
     *  POST data to the given endpoint.
     *
     * @param endpointURL Endpoint url.
     * @param params parameters.
     *      1. payloadData      payload data.
     *      2. headers          headers (optional).
     *      3. eventHandlers    event handlers.
     */
    void httpPost(String endpointURL, Object... params);
}
