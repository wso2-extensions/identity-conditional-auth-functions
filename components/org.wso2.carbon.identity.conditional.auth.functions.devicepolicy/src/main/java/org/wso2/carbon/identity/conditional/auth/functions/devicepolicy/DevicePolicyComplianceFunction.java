/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.devicepolicy;

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.base.JsBaseAuthenticationContext;

/**
 * JS function that checks device policy compliance for the current authentication context,
 * registered as {@code isDevicePolicyCompliant}.
 */
@FunctionalInterface
public interface DevicePolicyComplianceFunction {

    /**
     * Evaluates the given device policy against the verified device data on the authentication
     * context.
     *
     * @param context    Authentication context wrapper exposed to the JS engine.
     * @param policyName Name of the device policy to evaluate.
     * @return {@code null} if compliant; otherwise a {@code policyName:reason} or comma-separated
     *         field-list string describing why evaluation did not pass.
     */
    String isCompliant(JsBaseAuthenticationContext context, String policyName);
}
