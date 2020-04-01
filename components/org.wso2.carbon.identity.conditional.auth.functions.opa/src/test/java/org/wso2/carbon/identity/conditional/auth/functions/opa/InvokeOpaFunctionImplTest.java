

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

        package org.wso2.carbon.identity.conditional.auth.functions.opa;

        import org.apache.http.HttpEntity;
        import org.apache.http.StatusLine;
        import org.apache.http.client.config.RequestConfig;
        import org.apache.http.client.methods.CloseableHttpResponse;
        import org.apache.http.client.methods.HttpPost;
        import org.apache.http.entity.InputStreamEntity;
        import org.apache.http.impl.client.CloseableHttpClient;
        import org.apache.http.impl.client.HttpClientBuilder;
        import org.junit.runner.RunWith;
        import org.junit.runners.Parameterized;
        import org.mockito.Matchers;
        import org.mockito.Mock;
        import org.mockito.Mockito;
        import org.powermock.api.mockito.PowerMockito;
        import org.powermock.core.classloader.annotations.PowerMockIgnore;
        import org.powermock.core.classloader.annotations.PrepareForTest;
        import org.powermock.modules.junit4.PowerMockRunner;
        import org.powermock.modules.junit4.PowerMockRunnerDelegate;
        import org.testng.IObjectFactory;
        import org.testng.annotations.AfterMethod;
        import org.testng.annotations.BeforeMethod;
        import org.testng.annotations.ObjectFactory;
        import org.testng.annotations.Test;
        import org.wso2.carbon.identity.application.authentication.framework.AsyncProcess;
        import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsGraphBuilder;
        import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
        import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
        import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsStep;
        import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsSteps;
        import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
        import org.wso2.carbon.identity.conditional.auth.functions.common.utils.ConfigProvider;
        import org.wso2.carbon.identity.conditional.auth.functions.opa.InvokeOpaFunctionImpl;

        import java.io.ByteArrayInputStream;
        import java.util.HashMap;
        import java.util.Map;

        import static org.mockito.Matchers.anyString;
        import static org.mockito.MockitoAnnotations.initMocks;
        import static org.powermock.api.mockito.PowerMockito.*;

        @RunWith(PowerMockRunner.class)
        @PrepareForTest({JsGraphBuilder.class, HttpClientBuilder.class, RequestConfig.class, RequestConfig.Builder.class, AsyncProcess.class})
        @PowerMockIgnore("jdk.internal.reflect.*")
        public class InvokeOpaFunctionImplTest {

            @Mock
            private HttpClientBuilder mockBuil, mockBuilCon;

            @Mock
            private RequestConfig mockCon;

            @Mock
            private ConfigProvider conPro;

            @Mock
            private RequestConfig.Builder bui, bui1, conTime, reqTime, sockTime;


            @Mock
            private AsyncProcess mockAPro;


            private CloseableHttpClient httpClient;
            private HttpPost request;
            private HttpEntity entity;
            private StatusLine statusline;
            private CloseableHttpResponse response;
            private InvokeOpaFunctionImpl serviceInvoker;


//            @BeforeMethod(alwaysRun = true)
            @BeforeMethod
            public void setup() throws Exception {
                initMocks(this);
                this.httpClient = mock(CloseableHttpClient.class);
                this.request = mock(HttpPost.class);
                this.response = mock(CloseableHttpResponse.class);
                this.entity = mock(HttpEntity.class);
                this.statusline = mock(StatusLine.class);


                mockCon = mock(RequestConfig.class);
                conPro = mock(ConfigProvider.class);
                bui = mock(RequestConfig.Builder.class);
                bui1 = mock(RequestConfig.Builder.class);
                conTime = mock(RequestConfig.Builder.class);
                reqTime = mock(RequestConfig.Builder.class);
                sockTime = mock(RequestConfig.Builder.class);


                mockStatic(RequestConfig.class);
                when(RequestConfig.custom()).thenReturn(bui);
                when(bui.setConnectTimeout(5000)).thenReturn(conTime);
                when(conTime.setConnectionRequestTimeout(5000)).thenReturn(reqTime);
                when(reqTime.setSocketTimeout(5000)).thenReturn(sockTime);
                when(sockTime.build()).thenReturn(mockCon);


                mockStatic(HttpClientBuilder.class);
                mockBuil = mock(HttpClientBuilder.class);
                mockBuilCon = mock(HttpClientBuilder.class);

                when(HttpClientBuilder.create()).thenReturn(mockBuil);
                when(mockBuil.setDefaultRequestConfig(mockCon)).thenReturn(mockBuilCon);
                when(mockBuilCon.build()).thenReturn(httpClient);


                this.serviceInvoker = new InvokeOpaFunctionImpl();

                mockAPro = mock(AsyncProcess.class);

                System.out.println("printed from setup:");

            }

//            @Test(alwaysRun = true)
            @Test
            public void test() throws Exception {

                    JsAuthenticationContext mockContext = mock(JsAuthenticationContext.class);
                    JsSteps mockSteps = mock(JsSteps.class);
                    JsStep mockSlot = mock(JsStep.class);
                    JsAuthenticatedUser user = mock(JsAuthenticatedUser.class);

                    when(statusline.getStatusCode()).thenReturn(200);
                    when(response.getStatusLine()).thenReturn(statusline);
                    when(response.getEntity()).thenReturn(
                            new InputStreamEntity(
                                    new ByteArrayInputStream(
                                            "{\"message\":\"success\"}".getBytes())));
                    when(httpClient.execute(Matchers.any(HttpPost.class))).thenReturn(response);

                    Map<String, Object> events = new HashMap<String, Object>();
                    events.put("onSuccess", null);
                    events.put("onFail", null);


                    Map<String, String> options = new HashMap<String, String>();
                    options.put("sendClaims", "false");
                    options.put("sendRoles", "true");


                    Map payload = Mockito.mock(Map.class);
                    when(payload.get("context")).thenReturn(mockContext);
                    when((JsSteps) mockContext.getMember(anyString())).thenReturn(mockSteps);
                    when((JsStep) mockSteps.getSlot(1)).thenReturn(mockSlot);
                    when((JsAuthenticatedUser) mockSlot.getMember(anyString())).thenReturn(user);
                    when((String) user.getMember(anyString())).thenReturn("PRIMARY");

                    Object roles[] = {"Application/Smal2-web-app", "Application/travelocity.com", "admin"};
                    when(user.getMember(FrameworkConstants.JSAttributes.JS_LOCAL_ROLES)).thenReturn(roles);

//                    whenNew(AsyncProcess.class).withArguments(Mockito.any(AsyncCaller.class)).thenReturn(mockAPro);
                    System.out.println("pass the test");


                    mockStatic(JsGraphBuilder.class);
                    PowerMockito.doNothing().when(JsGraphBuilder.class, "addLongWaitProcess", Mockito.any(AsyncProcess.class), Mockito.anyMap());


                    serviceInvoker.invokeOPA("http://localhost:8181/v1/data/play/policy", payload, options, events);


                    System.out.println("pass the test");

            }


            @ObjectFactory
            public IObjectFactory getObjectFactory() {
                return new org.powermock.modules.testng.PowerMockObjectFactory();
            }

            @AfterMethod(alwaysRun = true)
            public void teardown() {
                System.out.println("---teardown---");
            }


        }
