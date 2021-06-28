/*
 *  Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.choreo;

import java.util.Map;

/**
 * Function to send HTTP requests to the Choreo and get the response synchronously.
 */
@FunctionalInterface
public interface CallChoreoFunction {

    /**
     * Sends data to Choreo and get the response from the Choreo service.
     * The payload  and the return value from the Choreo are both JSON structure, which needs to the contract between
     * the service and authentication script
     *
     * @param connectionMetaData Metadata to call the endpoint. This connectionMetaData map consists with connection url
     *                          (connectionMetaData.url) and api-key (connectionMetaData.apikey)
     * @param payloadData        payload data.
     * @param eventHandlers      event handlers.
     */
    void callChoreo(Map<String, String> connectionMetaData, Map<String, Object> payloadData,
                    Map<String, Object> eventHandlers);
}
