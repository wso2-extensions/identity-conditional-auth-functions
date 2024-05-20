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

package org.wso2.carbon.identity.conditional.auth.functions.utils;

import org.apache.commons.lang.StringUtils;
import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Implementation of the {@link FilterAuthenticatorsFunction}.
 */
public class FilterAuthenticatorsFunctionImpl implements FilterAuthenticatorsFunction {
    @Override
    @HostAccess.Export
    public Map<String, Map<String, String>> filterAuthenticators(List<Map<String, String>> authenticatorOptions,
                                                                 String excludeAuthenticator) {

        Map<String, Map<String, String>> result = new HashMap<>();
        int index = 0;

        if (authenticatorOptions != null) {
            for (Map<String, String> option : authenticatorOptions) {
                String idp = option.get(FrameworkConstants.JSAttributes.IDP);
                String authenticator = option.get(FrameworkConstants.JSAttributes.AUTHENTICATOR);

                if (!StringUtils.equals(excludeAuthenticator, authenticator)) {
                    Map<String, String> idpMap = new HashMap<>();
                    if (FrameworkConstants.LOCAL_IDP_NAME.equals(idp)) {
                        idpMap.put(FrameworkConstants.JSAttributes.AUTHENTICATOR, authenticator);
                    } else {
                        idpMap.put(FrameworkConstants.JSAttributes.IDP, idp);
                    }
                    result.put(String.valueOf(index++), idpMap);
                }
            }
        }
        return result;
    }
}
