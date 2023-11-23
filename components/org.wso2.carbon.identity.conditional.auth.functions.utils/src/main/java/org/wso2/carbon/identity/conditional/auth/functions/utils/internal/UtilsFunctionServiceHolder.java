/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.conditional.auth.functions.utils.internal;

import org.wso2.carbon.identity.application.authentication.framework.JsFunctionRegistry;

/**
 * Class to hold services discovered via OSGI on this component.
 */
public class UtilsFunctionServiceHolder {

    private static UtilsFunctionServiceHolder instance = new UtilsFunctionServiceHolder();

    private JsFunctionRegistry jsFunctionRegistry;

    public static UtilsFunctionServiceHolder getInstance() {

        return instance;
    }
    private UtilsFunctionServiceHolder(){
    }

    public JsFunctionRegistry getJsFunctionRegistry() {

        return jsFunctionRegistry;
    }

    public void setJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        this.jsFunctionRegistry = jsFunctionRegistry;
    }
}
