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

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.JsFunctionRegistry;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.loader.UIBasedConfigurationLoader;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JSExecutionSupervisor;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsBaseGraphBuilderFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsFunctionRegistryImpl;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsGenericGraphBuilderFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsGraphBuilderFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsWrapperFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsWrapperFactoryProvider;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.graaljs.JsGraalGraphBuilderFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.graaljs.JsGraalWrapperFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.sequence.impl.AsyncSequenceExecutor;
import org.wso2.carbon.identity.application.authentication.framework.handler.sequence.impl.GraphBasedSequenceHandler;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.api.MockAuthenticator;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.api.SubjectCallback;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.idp.mgt.dao.CacheBackedIdPMgtDAO;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

import javax.servlet.AsyncContext;
import javax.servlet.DispatcherType;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.Part;
import javax.xml.stream.XMLStreamException;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

/**
 * Framework runner for Javascript based Sequence execution.
 */
public class JsSequenceHandlerRunner {

    private static final Log log = LogFactory.getLog(JsSequenceHandlerRunner.class);

    protected GraphBasedSequenceHandler graphBasedSequenceHandler = new GraphBasedSequenceHandler();
    protected UIBasedConfigurationLoader configurationLoader;
    protected JsGenericGraphBuilderFactory graphBuilderFactory;
    protected  JSExecutionSupervisor jsExecutionSupervisor;

    private JsFunctionRegistryImpl jsFunctionRegistry;
    private URL applicationAuthenticatorConfigFileLocation;

    public static final int THREAD_COUNT = 1;
    public static final long SUPERVISOR_TIMEOUT = 500000L;

    private static final String DEFAULT_APPLICATION_AUTHENTICATION_XML_FILE_NAME = "application-authentication-test.xml";

    public void init(URL applicationAuthenticatorConfigFileLocation, String scriptEngine)
            throws InvocationTargetException, NoSuchFieldException, IllegalAccessException {

        this.applicationAuthenticatorConfigFileLocation = applicationAuthenticatorConfigFileLocation;
        configurationLoader = new UIBasedConfigurationLoader();

        if (scriptEngine.contentEquals(FrameworkConstants.JSAttributes.NASHORN)) {
            graphBuilderFactory = new JsGraphBuilderFactory();
        } else if (scriptEngine.contentEquals(FrameworkConstants.JSAttributes.GRAALJS)) {
            graphBuilderFactory = new JsGraalGraphBuilderFactory();
        }
        jsFunctionRegistry = new JsFunctionRegistryImpl();
        FrameworkServiceDataHolder.getInstance().setJsFunctionRegistry(jsFunctionRegistry);

        jsExecutionSupervisor = new JSExecutionSupervisor(THREAD_COUNT, SUPERVISOR_TIMEOUT);
        FrameworkServiceDataHolder.getInstance().setJsExecutionSupervisor(jsExecutionSupervisor);

        graphBuilderFactory.init();
        FrameworkServiceDataHolder.getInstance().setJsGenericGraphBuilderFactory(graphBuilderFactory);

        Field wrapperFactory = JsWrapperFactoryProvider.class.getDeclaredField("jsWrapperBaseFactory");
        wrapperFactory.setAccessible(true);
        if (graphBuilderFactory instanceof JsGraphBuilderFactory) {
            wrapperFactory.set(JsWrapperFactoryProvider.getInstance(), new JsWrapperFactory());
        } else if (graphBuilderFactory instanceof  JsGraalGraphBuilderFactory) {
            wrapperFactory.set(JsWrapperFactoryProvider.getInstance(), new JsGraalWrapperFactory());
        }

        AsyncSequenceExecutor asyncSequenceExecutor = new AsyncSequenceExecutor();
        asyncSequenceExecutor.init();
        FrameworkServiceDataHolder.getInstance().setAsyncSequenceExecutor(asyncSequenceExecutor);

        if (applicationAuthenticatorConfigFileLocation == null) {
            this.applicationAuthenticatorConfigFileLocation = this.getClass().getClassLoader().getResource(
                    DEFAULT_APPLICATION_AUTHENTICATION_XML_FILE_NAME);
        }
        reset();
    }

    private void reset() throws InvocationTargetException {

        URL root = this.getClass().getClassLoader().getResource(".");
        File file = new File(root.getPath());
        System.setProperty("carbon.home", file.toString());
        resetAuthenticators();

        CacheBackedIdPMgtDAO cacheBackedIdPMgtDAO = mock(CacheBackedIdPMgtDAO.class);
        Field daoField = null;
        try {
            daoField = IdentityProviderManager.class.getDeclaredField("dao");
            daoField.setAccessible(true);
            daoField.set(IdentityProviderManager.getInstance(), cacheBackedIdPMgtDAO);

            Field configFilePathField = FileBasedConfigurationBuilder.class.getDeclaredField("configFilePath");
            configFilePathField.setAccessible(true);

            configFilePathField.set(null, applicationAuthenticatorConfigFileLocation.getPath());
        } catch (NoSuchFieldException e) {
            throw new InvocationTargetException(e, "Could not inject mock objects to test runtime");
        } catch (IllegalAccessException e) {
            throw new InvocationTargetException(e, "Failed to inject mock objects to test runtime");
        }
    }

    /**
     * Registeres a javascript function contribution implemented as Java Functional interface.
     *
     * @param functionName
     * @param function
     */
    public void registerJsFunction(String functionName, Object function) {

        jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, functionName, function);
    }

    public void handle(HttpServletRequest req, HttpServletResponse resp, AuthenticationContext context,
                       String tenantDomain) throws
            JsTestException {

        try {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain, true);
            graphBasedSequenceHandler.handle(req, resp, context);
        } catch (FrameworkException e) {
            throw new JsTestException("Error executing javascript based sequence handler", e);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    public SequenceConfig getSequenceConfig(AuthenticationContext context,
                                            ServiceProvider serviceProvider) throws JsTestException {

        try {
            return this.getSequenceConfig(context, Collections.<String, String[]>emptyMap(), serviceProvider);
        } catch (FrameworkException e) {
            throw new JsTestException(
                    "Error while getting the sequence config for the service provider: " + serviceProvider
                            .getApplicationName(), e);
        }
    }

    public SequenceConfig getSequenceConfig(AuthenticationContext context, Map<String, String[]> parameterMap,
                                            ServiceProvider serviceProvider) throws FrameworkException {

        return configurationLoader.getSequenceConfig(context, parameterMap, serviceProvider);
    }

    public HttpServletRequest createHttpServletRequest() {

        return new MockServletRequest();
    }

    public HttpServletResponse createHttpServletResponse() throws JsTestException {

        HttpServletResponse res = mock(HttpServletResponse.class);
        PrintWriter writer = new PrintWriter(System.out);
        try {
            doReturn(writer).when(res).getWriter();
        } catch (IOException e) {
            throw new JsTestException("Error in creating mock HttpServletResponse", e);
        }

        return res;
    }

    public ServiceProvider loadServiceProviderFromResource(String spFileName, Object loader) throws JsTestException {

        InputStream inputStream = loader.getClass().getResourceAsStream(spFileName);
        OMElement documentElement = null;
        try {
            documentElement = new StAXOMBuilder(inputStream).getDocumentElement();
        } catch (XMLStreamException e) {
            throw new JsTestException("Error in reading Service Provider file at : " + spFileName, e);
        }
        return ServiceProvider.build(documentElement);
    }

    public AuthenticationContext createAuthenticationContext(ServiceProvider serviceProvider) {

        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setServiceProviderName(serviceProvider.getApplicationName());
        authenticationContext.setTenantDomain("test_domain");
        authenticationContext.setCurrentStep(1);
        authenticationContext.setContextIdentifier(UUID.randomUUID().toString());
        return authenticationContext;
    }

    protected void resetAuthenticators() {

        FrameworkServiceDataHolder.getInstance().getAuthenticators().clear();
        FrameworkServiceDataHolder.getInstance().getAuthenticators()
                .add(new MockAuthenticator("BasicMockAuthenticator", new MockSubjectCallback()));
        FrameworkServiceDataHolder.getInstance().getAuthenticators().add(new MockAuthenticator("HwkMockAuthenticator"));
        FrameworkServiceDataHolder.getInstance().getAuthenticators().add(new MockAuthenticator("FptMockAuthenticator"));
    }

    public void addSubjectAuthenticator(String authenticatorName, String subject, Map<String, String> claims) {

        FrameworkServiceDataHolder.getInstance().getAuthenticators().removeIf(
                applicationAuthenticator -> applicationAuthenticator.getName().equals(authenticatorName));
        MockAuthenticator authenticator = new MockAuthenticator(authenticatorName,
                (SubjectCallback) context1 -> {
                    AuthenticatedUser user = createLocalAuthenticatedUserFromSubjectIdentifier(subject);
                    if (claims != null) {
                        for (Map.Entry<String, String> entry : claims.entrySet()) {
                            user.getUserAttributes().put(ClaimMapping.build(entry.getKey(), entry.getKey(),
                                    entry.getValue(), false), entry.getValue());
                        }
                    }
                    return user;
                });
        FrameworkServiceDataHolder.getInstance().getAuthenticators().add(authenticator);

    }

    private static AuthenticatedUser createLocalAuthenticatedUserFromSubjectIdentifier
            (String authenticatedSubjectIdentifier) {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserStoreDomain(IdentityUtil.getPrimaryDomainName());
        authenticatedUser.setUserName(MultitenantUtils.getTenantAwareUsername(authenticatedSubjectIdentifier));
        authenticatedUser.setTenantDomain(MultitenantUtils.getTenantDomain(authenticatedSubjectIdentifier));
        authenticatedUser.setAuthenticatedSubjectIdentifier(authenticatedSubjectIdentifier);
        authenticatedUser.setUserId(UUID.randomUUID().toString());

        return authenticatedUser;
    }

    protected static class MockSubjectCallback implements SubjectCallback, Serializable {

        private static final long serialVersionUID = 597048141496121100L;

        @Override
        public AuthenticatedUser getAuthenticatedUser(AuthenticationContext context) {

            AuthenticatedUser result = createLocalAuthenticatedUserFromSubjectIdentifier("test_user");
            result.getUserAttributes().put(ClaimMapping
                                                   .build("http://wso2.org/claims/givenname",
                                                          "http://wso2.org/claims/givenname", "Test", false),
                                           "Test");
            result.getUserAttributes().put(ClaimMapping
                                                   .build("http://wso2.org/claims/lastname",
                                                          "http://wso2.org/claims/lastname", "Test", false),
                                           "User");
            return result;
        }
    }

    public static class MockServletRequest implements HttpServletRequest {

        private Hashtable<String, Object> attributes = new Hashtable<>();

        @Override
        public String getAuthType() {

            return null;
        }

        @Override
        public Cookie[] getCookies() {

            return new Cookie[0];
        }

        @Override
        public long getDateHeader(String s) {

            return 0;
        }

        @Override
        public String getHeader(String s) {

            return null;
        }

        @Override
        public Enumeration<String> getHeaders(String s) {

            return null;
        }

        @Override
        public Enumeration<String> getHeaderNames() {

            return null;
        }

        @Override
        public int getIntHeader(String s) {

            return 0;
        }

        @Override
        public String getMethod() {

            return null;
        }

        @Override
        public String getPathInfo() {

            return null;
        }

        @Override
        public String getPathTranslated() {

            return null;
        }

        @Override
        public String getContextPath() {

            return null;
        }

        @Override
        public String getQueryString() {

            return null;
        }

        @Override
        public String getRemoteUser() {

            return null;
        }

        @Override
        public boolean isUserInRole(String s) {

            return false;
        }

        @Override
        public Principal getUserPrincipal() {

            return null;
        }

        @Override
        public String getRequestedSessionId() {

            return null;
        }

        @Override
        public String getRequestURI() {

            return null;
        }

        @Override
        public StringBuffer getRequestURL() {

            return null;
        }

        @Override
        public String getServletPath() {

            return null;
        }

        @Override
        public HttpSession getSession(boolean b) {

            return null;
        }

        @Override
        public HttpSession getSession() {

            return null;
        }

        @Override
        public boolean isRequestedSessionIdValid() {

            return false;
        }

        @Override
        public boolean isRequestedSessionIdFromCookie() {

            return false;
        }

        @Override
        public boolean isRequestedSessionIdFromURL() {

            return false;
        }

        @Override
        public boolean isRequestedSessionIdFromUrl() {

            return false;
        }

        @Override
        public boolean authenticate(HttpServletResponse httpServletResponse) throws IOException, ServletException {

            return false;
        }

        @Override
        public void login(String s, String s1) throws ServletException {

        }

        @Override
        public void logout() throws ServletException {

        }

        @Override
        public Collection<Part> getParts() throws IOException, ServletException {

            return null;
        }

        @Override
        public Part getPart(String s) throws IOException, ServletException {

            return null;
        }

        @Override
        public Object getAttribute(String s) {

            return attributes.get(s);
        }

        @Override
        public Enumeration<String> getAttributeNames() {

            return attributes.keys();
        }

        @Override
        public String getCharacterEncoding() {

            return null;
        }

        @Override
        public void setCharacterEncoding(String s) throws UnsupportedEncodingException {

        }

        @Override
        public int getContentLength() {

            return 0;
        }

        @Override
        public String getContentType() {

            return null;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {

            return null;
        }

        @Override
        public String getParameter(String s) {

            return null;
        }

        @Override
        public Enumeration<String> getParameterNames() {

            return null;
        }

        @Override
        public String[] getParameterValues(String s) {

            return new String[0];
        }

        @Override
        public Map<String, String[]> getParameterMap() {

            return null;
        }

        @Override
        public String getProtocol() {

            return null;
        }

        @Override
        public String getScheme() {

            return null;
        }

        @Override
        public String getServerName() {

            return null;
        }

        @Override
        public int getServerPort() {

            return 0;
        }

        @Override
        public BufferedReader getReader() throws IOException {

            return null;
        }

        @Override
        public String getRemoteAddr() {

            return null;
        }

        @Override
        public String getRemoteHost() {

            return null;
        }

        @Override
        public void setAttribute(String s, Object o) {

            attributes.put(s, o);
        }

        @Override
        public void removeAttribute(String s) {

            attributes.remove(s);
        }

        @Override
        public Locale getLocale() {

            return null;
        }

        @Override
        public Enumeration<Locale> getLocales() {

            return null;
        }

        @Override
        public boolean isSecure() {

            return false;
        }

        @Override
        public RequestDispatcher getRequestDispatcher(String s) {

            return null;
        }

        @Override
        public String getRealPath(String s) {

            return null;
        }

        @Override
        public int getRemotePort() {

            return 0;
        }

        @Override
        public String getLocalName() {

            return null;
        }

        @Override
        public String getLocalAddr() {

            return null;
        }

        @Override
        public int getLocalPort() {

            return 0;
        }

        @Override
        public ServletContext getServletContext() {

            return null;
        }

        @Override
        public AsyncContext startAsync() throws IllegalStateException {

            return null;
        }

        @Override
        public AsyncContext startAsync(ServletRequest servletRequest, ServletResponse servletResponse) throws
                IllegalStateException {

            return null;
        }

        @Override
        public boolean isAsyncStarted() {

            return false;
        }

        @Override
        public boolean isAsyncSupported() {

            return false;
        }

        @Override
        public AsyncContext getAsyncContext() {

            return null;
        }

        @Override
        public DispatcherType getDispatcherType() {

            return null;
        }
    }
}
