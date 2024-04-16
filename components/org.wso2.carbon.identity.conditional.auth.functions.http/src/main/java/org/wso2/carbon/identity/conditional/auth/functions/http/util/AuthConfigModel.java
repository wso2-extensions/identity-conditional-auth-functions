/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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
package org.wso2.carbon.identity.conditional.auth.functions.http.util;

import java.util.Map;

/**
 * Model class for the authentication configuration.
 */
public class AuthConfigModel {
    String type;
    private Map<String, Object> properties;

    public AuthConfigModel(String type, Map<String, Object> properties) {
        this.type = type;
        this.properties = properties;
    }

    public void setType(String type) {
        this.type = type;
    }

    public void setProperties(Map<String, Object> properties) {
        this.properties = properties;
    }

    public String getType() {
        return type;
    }

    public Map<String, Object> getProperties() {
        return properties;
    }
}
