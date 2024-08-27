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

package org.wso2.carbon.identity.conditional.auth.functions.common.model;

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsGenericGraphBuilderFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.graaljs.JsGraalGraphBuilderFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.openjdk.nashorn.JsOpenJdkNashornGraphBuilderFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.conditional.auth.functions.common.model.graaljs.JsGraalUtils;
import org.wso2.carbon.identity.conditional.auth.functions.common.model.nashorn.JsNashornUtils;
import org.wso2.carbon.identity.conditional.auth.functions.common.model.openjdk.nashorn.JsOpenJdkNashornUtils;

public class JsUtilsProvider {

    private static final JsUtilsProvider jsUtilsProvider = new JsUtilsProvider();

    private final JsUtils jsUtils;

    private JsUtilsProvider() {

        JsGenericGraphBuilderFactory jsGraphBuilderFactory =
                FrameworkUtils.createJsGenericGraphBuilderFactoryFromConfig();
        if (jsGraphBuilderFactory instanceof JsOpenJdkNashornGraphBuilderFactory) {
            jsUtils = new JsOpenJdkNashornUtils();
        } else if (jsGraphBuilderFactory instanceof JsGraalGraphBuilderFactory) {
            jsUtils = new JsGraalUtils();
        } else {
            jsUtils = new JsNashornUtils();
        }
    }

    public static JsUtilsProvider getInstance() {

        return jsUtilsProvider;
    }

    public JsUtils getJsUtils() {

        return jsUtils;
    }

}
