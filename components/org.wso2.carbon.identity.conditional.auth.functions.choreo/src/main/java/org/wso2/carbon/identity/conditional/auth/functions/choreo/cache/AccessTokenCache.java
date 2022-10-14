package org.wso2.carbon.identity.conditional.auth.functions.choreo.cache;

import org.wso2.carbon.identity.core.cache.BaseCache;

public class AccessTokenCache extends BaseCache<String, String> {

    private static final String ACCESS_TOKEN_CACHE_NAME = "AccessTokenCache";

    private AccessTokenCache() {

        super(ACCESS_TOKEN_CACHE_NAME);
    }

    private static class AccessTokenCacheHolder {
        static final AccessTokenCache instance = new AccessTokenCache();
    }

    public static AccessTokenCache getInstance(){
        return AccessTokenCacheHolder.instance;
    }

}
