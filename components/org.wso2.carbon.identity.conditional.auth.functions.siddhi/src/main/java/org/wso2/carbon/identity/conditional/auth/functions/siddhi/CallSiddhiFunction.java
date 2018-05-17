/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.conditional.auth.functions.siddhi;

import java.util.Map;
import java.util.function.Consumer;

/**
 * Function to check if the given user has the given role.
 * The purpose is to perform dynamic authentication selection based on user role.
 */
@FunctionalInterface
public interface CallSiddhiFunction {

    /**
     *  Call siddhi to get decision.
     *
     * @param siddhiAppName Siddhi application name.
     * @param inStreamName input stream name.
     * @param outStreamName output stream name.
     * @param payloadData payload data.
     * @param callback callback function.
     * @param eventHandlers event handlers.
     */
    void callSiddhi(String siddhiAppName, String inStreamName, String outStreamName,
                       Map<String, Object> payloadData,
                       Consumer<Map<String, Object>> callback, Map<String, Object> eventHandlers);
}
