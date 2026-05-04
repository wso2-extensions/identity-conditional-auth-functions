/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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
 * Cache that stores {@link CachedToken} instances keyed by consumer key.
 * Each entry holds the access token string and its expiry epoch atomically,
 * eliminating the need for a separate token cache and expiry cache.
 */
public class APIAccessTokenExpiryCache extends BaseCache<String, CachedToken> {

    private static final String ACCESS_TOKEN_EXPIRY_CACHE_NAME = "APIAccessTokenExpiryCache";

    private APIAccessTokenExpiryCache() {

        super(ACCESS_TOKEN_EXPIRY_CACHE_NAME);
    }

    private static class ExpiryTokenCacheHolder {

        static final APIAccessTokenExpiryCache INSTANCE = new APIAccessTokenExpiryCache();
    }

    public static APIAccessTokenExpiryCache getInstance() {

        return ExpiryTokenCacheHolder.INSTANCE;
    }
}
