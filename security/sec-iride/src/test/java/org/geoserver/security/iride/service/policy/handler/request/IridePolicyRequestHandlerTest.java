/*
 *  GeoServer Security Provider plugin with which doing authentication and authorization operations using CSI-Piemonte IRIDE Service.
 *  Copyright (C) 2016  Regione Piemonte (www.regione.piemonte.it)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package org.geoserver.security.iride.service.policy.handler.request;

import static org.hamcrest.Matchers.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.io.IOUtils;
import org.geoserver.security.iride.service.policy.IridePolicy;
import org.geoserver.security.iride.service.policy.IridePolicyManager;
import org.geoserver.security.iride.service.policy.handler.IridePolicyRequestHandler;
import org.geoserver.security.iride.util.builder.http.HttpPostBuilder;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestContextManager;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.support.DependencyInjectionTestExecutionListener;
import org.springframework.util.ResourceUtils;

import test.org.geoserver.security.iride.util.factory.util.UrlValidatorFactory;

/**
 * <code>IRIDE</code> service "policy" <em>request</em>handler <code>JUnit</code> Test.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
@RunWith(Parameterized.class)
@ContextConfiguration(locations = {
    "classpath:/testContext.xml",
    "classpath:/testEntitiesContext.xml",
    "classpath:/templateContext.xml",
})
@TestExecutionListeners({ DependencyInjectionTestExecutionListener.class })
public final class IridePolicyRequestHandlerTest {

    private static final String RESOURCE_LOCATION_PATTERN = "classpath:iride/soap/response/%s.xml";

    private static String serverURL;

    private final TestContextManager testContextManager;

    /**
     * <code>IRIDE</code> service "policy": one of the the various service callable operations.
     */
    private final IridePolicy policy;

    private final String paramsBeanName;

    private Map<String, Object> params;

    /**
     * <code>Spring</code> <a href="https://spring.io/understanding/application-context">application context</a>.
     */
    @Autowired
    private ApplicationContext applicationContext;

    /**
     * Manager class for <code>IRIDE</code> service "policy" handlers.
     */
    private IridePolicyManager policyManager;

    /**
     * Constructor.
     *
     * @param policy
     */
    public IridePolicyRequestHandlerTest(IridePolicy policy, String paramsBeanName) {
        this.testContextManager = new TestContextManager(this.getClass());

        this.policy         = policy;
        this.paramsBeanName = paramsBeanName;
    }

    /**
     *
     * @return
     * @throws IOException
     */
    @Parameters(name = "Handling {0} Policy request with {1} params")
    public static Collection<Object[]> parameters() throws IOException {
        return Arrays.asList(
            new Object[][] {
                { IridePolicy.FIND_RUOLI_FOR_PERSONA_IN_APPLICATION, "irideIdentityAndApplication" },
                { IridePolicy.FIND_RUOLI_FOR_PERSONA_IN_USE_CASE, "irideIdentityAndUseCase" },
                { IridePolicy.FIND_USE_CASES_FOR_PERSONA_IN_APPLICATION, "irideIdentityAndApplication" },
                { IridePolicy.GET_INFO_PERSONA_IN_USE_CASE, "irideIdentityAndUseCase" },
                { IridePolicy.IDENTIFICA_USER_PASSWORD, "usernameAndPassword" },
                { IridePolicy.IS_IDENTITA_AUTENTICA, "irideIdentityOnly" },
                { IridePolicy.IS_PERSONA_AUTORIZZATA_IN_USE_CASE, "irideIdentityAndUseCase" },
                { IridePolicy.IS_PERSONA_IN_RUOLO, "irideIdentityAndRole" },
            }
        );
    }

    /**
     * <code>IRIDE</code> service "policy" <em>request</em>handler test class preparation.
     *
     * @throws Exception
     */
    @BeforeClass
    public static void setupClass() throws Exception {
        serverURL = "http://local-applogic-nmsf2e.csi.it/pep_wsfad_nmsf_policy/services/PolicyEnforcerBase";

        // Preliminary test assertions
        assertTrue(UrlValidatorFactory.createUrlValidator().isValid(serverURL));
    }

    /**
     * <code>IRIDE</code> service "policy" <em>request</em>handler test preparation and setup.
     *
     * @throws Exception
     */
    @Before
    @SuppressWarnings("unchecked")
    public void setup() throws Exception {
        // Preparation of test instance
        this.testContextManager.prepareTestInstance(this);

        this.policyManager = this.applicationContext.getBean("policyManager", IridePolicyManager.class);
        this.params        = this.applicationContext.getBean(this.paramsBeanName, Map.class);

        // Preliminary test assertions
        assertThat(this.policyManager, not(nullValue()));
        assertThat(this.params, is(not(nullValue())));
        assertThat(this.params.entrySet(), is(not(empty())));
    }

    /**
     * Test method for {@link org.geoserver.security.iride.service.policy.handler.IridePolicyRequestHandler#handleRequest(java.lang.String, java.util.Map)}.
     *
     * @throws IOException
     */
    @Test
    public void test() throws IOException {
        final boolean hasHandler = this.policyManager.hasPolicyRequestHandler(this.policy);

        assertTrue(hasHandler);

        final IridePolicyRequestHandler handler = this.prepareHandler(this.policyManager.getPolicyRequestHandler(this.policy));

        assertThat(handler, is(not(nullValue())));
        assertThat(this.policy, is(handler.getPolicy()));

        final String result = handler.handleRequest(serverURL, this.params);

        assertThat(result, not(isEmptyOrNullString()));
    }

    /**
     *
     * @param handler
     * @return
     */
    private IridePolicyRequestHandler prepareHandler(IridePolicyRequestHandler handler) {
        final HttpPostBuilder spied = spy(handler.getHttpPostBuilder());

        when(spied.build(eq(serverURL), anyString(), org.mockito.Matchers.any(Header[].class))).then(new Answer<PostMethod>() {

            /*
             * (non-Javadoc)
             * @see org.mockito.stubbing.Answer#answer(org.mockito.invocation.InvocationOnMock)
             */
            @Override
            public PostMethod answer(final InvocationOnMock invocation) throws Throwable {
                return new PostMethod() {

                    /*
                     * (non-Javadoc)
                     * @see org.apache.commons.httpclient.methods.PostMethod#getName()
                     */
                    @Override
                    public String getName() {
                        return "FileMethod";
                    }

                    /*
                     * (non-Javadoc)
                     * @see org.apache.commons.httpclient.HttpMethodBase#getResponseBodyAsString()
                     */
                    @Override
                    public String getResponseBodyAsString() throws IOException {
                        final String resourceLocation = String.format(RESOURCE_LOCATION_PATTERN, IridePolicyRequestHandlerTest.this.policy.getServiceName());
                        try (final InputStream in = ResourceUtils.getURL(resourceLocation).openStream()) {
                          return IOUtils.toString(in);
                        }
                    }
                };
            }
        });

        handler.setHttpPostBuilder(spied);

        return handler;
    }

}
