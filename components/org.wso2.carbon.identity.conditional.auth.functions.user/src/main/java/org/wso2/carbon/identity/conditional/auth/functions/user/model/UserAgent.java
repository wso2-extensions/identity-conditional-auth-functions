/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.conditional.auth.functions.user.model;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import ua_parser.Device;
import ua_parser.OS;
import ua_parser.Parser;

import java.io.IOException;

public class UserAgent {
    private static final Log LOG = LogFactory.getLog(UserAgent.class);
    private static Parser parser;
    private String rawString;
    private ua_parser.UserAgent browser;
    private OS platform;
    private Device device;

    public UserAgent(String rawString) {
        this.rawString = rawString;
        this.browser = getParser().parseUserAgent(rawString);
        this.platform = getParser().parseOS(rawString);
        this.device = getParser().parseDevice(rawString);
    }

    public static synchronized Parser getParser() {
        if (parser == null) {
            try {
                parser = new Parser();
            } catch (IOException e) {
                LOG.error("Unable to initialize the user agent parser: ", e);
            }
        }
        return parser;
    }

    public String getRawString() {
        return rawString;
    }

    public void setRawString(String rawString) {
        this.rawString = rawString;
        this.browser = getParser().parseUserAgent(rawString);
        this.platform = getParser().parseOS(rawString);
        this.device = getParser().parseDevice(rawString);
    }

    public String getBrowser() {
        return browser.family;
    }

    public String getPlatform() {
        return platform.family;
    }

    public String getDevice() {
        return device.family;
    }

}
