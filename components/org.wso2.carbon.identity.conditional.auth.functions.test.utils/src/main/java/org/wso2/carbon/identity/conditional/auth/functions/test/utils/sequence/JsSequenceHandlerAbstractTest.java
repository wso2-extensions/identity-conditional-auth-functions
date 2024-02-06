/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Parameters;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;

/**
 * Abstract test used for Javascript based sequence handling.
 */
public class JsSequenceHandlerAbstractTest {

    private static final Log log = LogFactory.getLog(JsSequenceHandlerAbstractTest.class);

    protected JsSequenceHandlerRunner sequenceHandlerRunner;

    protected String getApplicationAuthenticatorFileName() {

        return null;
    }

    @BeforeClass
    protected void initialize() throws IOException {

        URL identityXmlUrl = this.getClass().getClassLoader().getResource("repository/conf/identity/identity.xml");
        if (identityXmlUrl == null) {
            log.error("Unable to locate \"identity.xml\"");
        } else {
            File file = new File(identityXmlUrl.getPath());
            if(!file.exists()) {
                //Copy default identity xml into temp location and use it.
                URL url = JsSequenceHandlerAbstractTest.class.getClassLoader().getResource("repository/conf/identity/identity.xml");
                InputStream inputStream = url.openStream();
                File f;
                WritableByteChannel targetChannel;
                try (ReadableByteChannel inputChannel = Channels.newChannel(inputStream)) {
                    f = File.createTempFile(this.getClass().getSimpleName(), "identity.xml");
                    try (FileOutputStream fos = new FileOutputStream(f)) {
                        targetChannel = fos.getChannel();
                        //Transfer data from input channel to output channel
                        ((FileChannel) targetChannel).transferFrom(inputChannel, 0, Long.MAX_VALUE);
                    }
                }
                inputStream.close();
                targetChannel.close();
                identityXmlUrl = f.toURI().toURL();
            }
            IdentityConfigParser.getInstance(identityXmlUrl.getPath());
        }
    }

    @BeforeMethod
    @Parameters({"scriptEngine"})
    protected void setUp(String scriptEngine) throws Exception {

        if (sequenceHandlerRunner == null) {
            sequenceHandlerRunner = new JsSequenceHandlerRunner();
            URL url = null;
            String applicationAuthenticatorFileName = getApplicationAuthenticatorFileName();
            if (applicationAuthenticatorFileName != null) {
                url = this.getClass().getClassLoader().getResource(applicationAuthenticatorFileName);
            }
            sequenceHandlerRunner.init(url, scriptEngine);
        }
        FrameworkServiceDataHolder.getInstance().setAdaptiveAuthenticationAvailable(true);
    }
}
