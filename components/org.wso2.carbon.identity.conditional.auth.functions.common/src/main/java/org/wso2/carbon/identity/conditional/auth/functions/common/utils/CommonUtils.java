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

package org.wso2.carbon.identity.conditional.auth.functions.common.utils;

import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.conditional.auth.functions.common.internal.FunctionsDataHolder;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CommonUtils {

    public static String getConnectorConfig(String key, String tenantDomain) throws IdentityEventException {

        //TODO check whether there is a more optimized way
        try {
            Property[] connectorConfigs;
            IdentityGovernanceService identityGovernanceService = FunctionsDataHolder.getInstance()
                    .getIdentityGovernanceService();
            if (identityGovernanceService != null) {
                connectorConfigs = identityGovernanceService.getConfiguration(new String[]{key}, tenantDomain);
                if (connectorConfigs != null && connectorConfigs.length > 0) {
                    return connectorConfigs[0].getValue();
                }
            }
            return null;
        } catch (IdentityGovernanceException e) {
            throw new IdentityEventException("Error while getting connector configurations for property :" + key, e);
        }
    }

    public static Map<String, Object> getPayloadDataMap(Map<String, Object> payloadData) {

        if (payloadData == null) {
            return new HashMap<>();
        }
        Map<String, Object> payloadDataMap = new HashMap<>();
        for (Map.Entry<String, Object> entry : payloadData.entrySet()) {
            Object value = entry.getValue();
            if (value instanceof Map) {
                payloadDataMap.put(entry.getKey(), getPayloadDataMap((Map<String, Object>) value));
            } else if (value instanceof List) {
                payloadDataMap.put(entry.getKey(), processList((List<Object>) value));
            } else {
                payloadDataMap.put(entry.getKey(), value);
            }
        }
        return payloadDataMap;
    }

    private static List<Object> processList(List<Object> list) {

        List<Object> resultList = new ArrayList<>();
        for (Object item : list) {
            if (item instanceof Map) {
                resultList.add(getPayloadDataMap((Map<String, Object>) item));
            } else if (item instanceof List) {
                resultList.add(processList((List<Object>) item));
            } else {
                resultList.add(item);
            }
        }
        return resultList;
    }
}
