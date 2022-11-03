package org.wso2.carbon.identity.conditional.auth.functions.choreo.cache;

import org.wso2.carbon.identity.core.cache.BaseCache;

/**
 * The cache implementation which stores the access tokens received from Choreo.
 */
public class AccessTokenCache extends BaseCache<String, String> {

    private static final String ACCESS_TOKEN_CACHE_NAME = "AccessTokenCache";

    private AccessTokenCache() {

        super(ACCESS_TOKEN_CACHE_NAME);
    }

    private static class AccessTokenCacheHolder {
        static final AccessTokenCache INSTANCE = new AccessTokenCache();
    }

    public static AccessTokenCache getInstance() {
        return AccessTokenCacheHolder.INSTANCE;
    }

}
