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

package org.wso2.carbon.identity.conditional.auth.functions.test.utils.serialize;

import com.google.gson.JsonElement;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import org.graalvm.polyglot.proxy.ProxyArray;
import org.graalvm.polyglot.proxy.ProxyObject;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.graaljs.JsGraalWritableParameters;

import java.lang.reflect.Array;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class JsGraalWritableParametersSerializer
        implements JsonSerializer<JsGraalWritableParameters> {

    @Override
    public JsonElement serialize(JsGraalWritableParameters src, Type typeOfSrc,
                                 JsonSerializationContext context) {
        return context.serialize(unwrap(src.getWrapped()));
    }

    @SuppressWarnings("unchecked")
    private Object unwrap(Object value) {
        if (value == null) {
            return null;
        }

        // Handle nested JsGraalWritableParameters recursively.
        if (value instanceof JsGraalWritableParameters) {
            return unwrap(((JsGraalWritableParameters) value).getWrapped());
        }

        // Handle ProxyObject (Graal polyglot map-like structure).
        if (value instanceof ProxyObject) {
            ProxyObject proxyObject = (ProxyObject) value;
            Map<String, Object> map = new LinkedHashMap<>();

            Object keyObj = proxyObject.getMemberKeys();
            if (keyObj instanceof Collection<?>) {
                for (Object k : (Collection<?>) keyObj) {
                    map.put(String.valueOf(k), unwrap(proxyObject.getMember(String.valueOf(k))));
                }
            } else if (keyObj instanceof Object[]) {
                for (Object k : (Object[]) keyObj) {
                    map.put(String.valueOf(k), unwrap(proxyObject.getMember(String.valueOf(k))));
                }
            } else if (keyObj instanceof Iterable<?>) {
                for (Object k : (Iterable<?>) keyObj) {
                    map.put(String.valueOf(k), unwrap(proxyObject.getMember(String.valueOf(k))));
                }
            } else if (keyObj != null) {
                // fallback: treat as single key
                map.put(String.valueOf(keyObj), unwrap(proxyObject.getMember(String.valueOf(keyObj))));
            }
            return map;
        }

        // Handle ProxyArray (Graal polyglot list-like structure).
        if (value instanceof ProxyArray) {
            ProxyArray array = (ProxyArray) value;
            long size = array.getSize();
            List<Object> list = new ArrayList<>();
            for (long i = 0; i < size; i++) {
                list.add(unwrap(array.get(i)));
            }
            return list;
        }

        // Handle Map.
        if (value instanceof Map) {
            Map<String, Object> result = new LinkedHashMap<>();
            ((Map<?, ?>) value).forEach((k, v) -> result.put(String.valueOf(k), unwrap(v)));
            return result;
        }

        // Handle List.
        if (value instanceof List) {
            List<Object> list = new ArrayList<>();
            for (Object item : (List<?>) value) {
                list.add(unwrap(item));
            }
            return list;
        }

        // Handle Arrays.
        if (value.getClass().isArray()) {
            int len = Array.getLength(value);
            List<Object> list = new ArrayList<>(len);
            for (int i = 0; i < len; i++) {
                list.add(unwrap(Array.get(value, i)));
            }
            return list;
        }

        // Primitive or plain type.
        return value;
    }
}
