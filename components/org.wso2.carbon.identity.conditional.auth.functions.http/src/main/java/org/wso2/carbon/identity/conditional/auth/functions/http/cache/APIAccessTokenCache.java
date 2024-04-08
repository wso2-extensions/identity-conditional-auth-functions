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
package org.wso2.carbon.identity.conditional.auth.functions.http.cache;

import org.wso2.carbon.identity.core.cache.BaseCache;

/**
 * The cache implementation which stores the access tokens received from API.
 */
public class APIAccessTokenCache extends BaseCache<String, String> {

    private static final String ACCESS_TOKEN_CACHE_NAME = "APIAccessTokenCache";

    private APIAccessTokenCache() {

        super(ACCESS_TOKEN_CACHE_NAME);
    }

    private static class AccessTokenCacheHolder {
        static final APIAccessTokenCache INSTANCE = new APIAccessTokenCache();
    }

    public static APIAccessTokenCache getInstance() {
        return AccessTokenCacheHolder.INSTANCE;
    }

}
