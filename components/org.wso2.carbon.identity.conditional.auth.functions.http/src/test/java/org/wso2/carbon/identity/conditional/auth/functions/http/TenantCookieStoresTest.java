/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.conditional.auth.functions.http;

import org.apache.http.client.CookieStore;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.conditional.auth.functions.http.util.TenantCookieStores;

import java.util.concurrent.atomic.AtomicLong;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotSame;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertTrue;

/**
 * Tests the per-tenant cookie store selection and eviction.
 */
public class TenantCookieStoresTest {

    private static final long IDLE_TIMEOUT = 1000;

    private AtomicLong now;

    @BeforeMethod
    public void setUp() {

        now = new AtomicLong(0);
    }

    private TenantCookieStores newStores(int maxTenants) {

        return new TenantCookieStores(maxTenants, IDLE_TIMEOUT, now::get);
    }

    @Test
    public void testSameTenantSharesStoreAndTenantsAreIsolated() {

        TenantCookieStores stores = newStores(10);
        CookieStore a = stores.get("a.com");
        a.addCookie(new BasicClientCookie("session", "a"));

        assertSame(stores.get("a.com"), a);
        CookieStore b = stores.get("b.com");
        assertNotSame(b, a);
        assertTrue(b.getCookies().isEmpty(), "A cookie of tenant a.com must not be visible to b.com.");
    }

    @Test
    public void testNullAndBlankTenantFallBackToSuperTenant() {

        TenantCookieStores stores = newStores(10);
        CookieStore viaNull = stores.get(null);
        assertSame(stores.get(" "), viaNull);
        assertSame(stores.get("carbon.super"), viaNull);
        assertEquals(stores.size(), 1);
    }

    @Test
    public void testLeastRecentlyUsedTenantDroppedWhenCapExceeded() {

        TenantCookieStores stores = newStores(2);
        CookieStore a = stores.get("a.com");
        now.incrementAndGet();
        CookieStore b = stores.get("b.com");
        now.incrementAndGet();
        stores.get("a.com"); // a is now more recent than b.
        now.incrementAndGet();
        stores.get("c.com");

        assertEquals(stores.size(), 2);
        assertSame(stores.get("a.com"), a);
        assertNotSame(stores.get("b.com"), b, "b.com was the least recently used and should have been dropped.");
    }

    @Test
    public void testIdleTenantDropped() {

        TenantCookieStores stores = newStores(10);
        CookieStore a = stores.get("a.com");
        now.set(IDLE_TIMEOUT + 1);
        stores.get("b.com");

        assertEquals(stores.size(), 1);
        assertNotSame(stores.get("a.com"), a, "An idle tenant should get a fresh cookie store.");
    }

    @Test
    public void testActiveTenantKept() {

        TenantCookieStores stores = newStores(10);
        CookieStore a = stores.get("a.com");
        for (int i = 0; i < 5; i++) {
            now.addAndGet(IDLE_TIMEOUT / 2);
            assertSame(stores.get("a.com"), a);
        }
    }

    @Test
    public void testClearDropsAllStores() {

        TenantCookieStores stores = newStores(10);
        stores.get("a.com");
        stores.get("b.com");
        stores.clear();
        assertEquals(stores.size(), 0);
    }
}
