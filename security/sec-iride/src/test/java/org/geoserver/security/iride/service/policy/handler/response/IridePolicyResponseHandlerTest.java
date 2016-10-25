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
package org.geoserver.security.iride.service.policy.handler.response;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.logging.Logger;

import javax.xml.transform.TransformerException;

import org.apache.commons.io.IOUtils;
import org.geoserver.security.iride.service.policy.IridePolicy;
import org.geoserver.security.iride.service.policy.IridePolicyManager;
import org.geoserver.security.iride.service.policy.handler.IridePolicyResponseHandler;
import org.geotools.util.logging.Logging;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestContextManager;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.support.DependencyInjectionTestExecutionListener;
import org.springframework.util.ResourceUtils;

/**
 * <code>IRIDE</code> service "policy" <em>response</em> handler <code>JUnit</code> Test.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
@RunWith(Parameterized.class)
@ContextConfiguration(locations = {
    "classpath:/testContext.xml",
})
@TestExecutionListeners({ DependencyInjectionTestExecutionListener.class })
public final class IridePolicyResponseHandlerTest {

    /**
     * Logger.
     */
    private static final Logger LOGGER = Logging.getLogger(IridePolicyResponseHandlerTest.class);

    private static final String RESOURCE_LOCATION_PATTERN = "classpath:iride/soap/response/%s.xml";

    private final TestContextManager testContextManager;

    /**
     * <code>IRIDE</code> service "policy": one of the the various service callable operations.
     */
    private final IridePolicy policy;

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
    public IridePolicyResponseHandlerTest(IridePolicy policy) {
        this.testContextManager = new TestContextManager(this.getClass());

        this.policy = policy;
    }

    /**
     *
     * @return
     * @throws IOException
     */
    @Parameters(name = "Handling {0} Policy response")
    public static Collection<Object[]> parameters() throws IOException {
        return Arrays.asList(
            new Object[][] {
                { IridePolicy.FIND_RUOLI_FOR_PERSONA_IN_APPLICATION },
                { IridePolicy.FIND_RUOLI_FOR_PERSONA_IN_USE_CASE },
                { IridePolicy.FIND_USE_CASES_FOR_PERSONA_IN_APPLICATION },
                { IridePolicy.GET_INFO_PERSONA_IN_USE_CASE },
                { IridePolicy.IDENTIFICA_USER_PASSWORD },
                { IridePolicy.IS_IDENTITA_AUTENTICA },
                { IridePolicy.IS_PERSONA_AUTORIZZATA_IN_USE_CASE },
                { IridePolicy.IS_PERSONA_IN_RUOLO },
            }
        );
    }

    /**
     * <code>IRIDE</code> service "policy" <em>request</em>handler test preparation and setup.
     *
     * @throws Exception
     */
    @Before
    public void setup() throws Exception {
        // Preparation of test instance
        this.testContextManager.prepareTestInstance(this);

        this.policyManager = this.applicationContext.getBean("policyManager", IridePolicyManager.class);

        // Preliminary test assertions
        assertThat(this.policyManager, not(nullValue()));
    }

    /**
     * Test method for {@link org.geoserver.security.iride.service.policy.handler.IridePolicyRequestHandler#handleResponse(java.lang.String)}.
     *
     * @throws IOException
     * @throws TransformerException
     */
    @Test
    public void test() throws IOException, TransformerException {
        final boolean hasHandler = this.policyManager.hasPolicyResponseHandler(this.policy);

        assertTrue(hasHandler);

        final IridePolicyResponseHandler handler = this.policyManager.getPolicyResponseHandler(this.policy);

        assertThat(handler, is(not(nullValue())));
        assertThat(this.policy, is(handler.getPolicy()));

        final Object result = handler.handleResponse(this.getIrideResponseAsString());

        assertThat(result, not(nullValue()));

        LOGGER.fine(String.format("Policy '%s' Response Object: %s", this.policy, result));
    }

    /**
     *
     * @param policy
     * @return
     * @throws IOException
     */
    private String getIrideResponseAsString() throws IOException {
        final String resourceLocation = String.format(RESOURCE_LOCATION_PATTERN, this.policy.getServiceName());
        try (final InputStream in = ResourceUtils.getURL(resourceLocation).openStream()) {
            return IOUtils.toString(in);
        }
    }

}
