/*
 * Copyright (c) 2018, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.http.internal;

import org.wso2.carbon.identity.application.authentication.framework.JsFunctionRegistry;
import org.wso2.carbon.security.keystore.service.IdentityKeyStoreGenerator;

public class HTTPFunctionsServiceHolder {

    private static HTTPFunctionsServiceHolder instance = new HTTPFunctionsServiceHolder();

    private JsFunctionRegistry jsFunctionRegistry;
    private IdentityKeyStoreGenerator identityKeyStoreGenerator;

    public static HTTPFunctionsServiceHolder getInstance() {

        return instance;
    }

    private HTTPFunctionsServiceHolder() {

    }

    public JsFunctionRegistry getJsFunctionRegistry() {

        return jsFunctionRegistry;
    }

    public void setJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        this.jsFunctionRegistry = jsFunctionRegistry;
    }

    public IdentityKeyStoreGenerator getIdentityKeyStoreGenerator() {

        return identityKeyStoreGenerator;
    }

    public void setIdentityKeyStoreGenerator(IdentityKeyStoreGenerator identityKeyStoreGenerator) {

        this.identityKeyStoreGenerator = identityKeyStoreGenerator;
    }
}
