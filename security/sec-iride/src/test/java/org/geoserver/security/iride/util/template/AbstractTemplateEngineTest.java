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
package org.geoserver.security.iride.util.template;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.util.Map;

import org.geoserver.security.iride.AbstractXmlUnitTest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestContextManager;

/**
 * Base class for <a href="http://freemarker.org/"><code>FreeMarker</code></a> {@link TemplateEngine} template compilation <code>JUnit</code> Test.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 * @see https://github.com/spring-projects/spring-framework/blob/master/spring-test/src/test/java/org/springframework/test/context/junit4/ParameterizedDependencyInjectionTests.java
 */
@RunWith(Parameterized.class)
@ContextConfiguration(locations = {
    "classpath:/testContext.xml",
    "classpath:/testEntitiesContext.xml",
    "classpath:/templateContext.xml"
})
public abstract class AbstractTemplateEngineTest extends AbstractXmlUnitTest {

    private final TestContextManager testContextManager;

    private final String templateName;

    private final String contextName;

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private TemplateEngine templateEngine;

    private Map<String, Object> context;

    /**
     * Constructor.<br />
     * Initializes {@link TestContextManager} instance.
     *
     * @param templateName
     * @param contextBeanName
     */
    protected AbstractTemplateEngineTest(String templateName, String contextBeanName) {
    	this.testContextManager = new TestContextManager(this.getClass());

        this.templateName = templateName;
        this.contextName  = contextBeanName;
    }

    /**
     * {@link TemplateEngine} test preparation and setup.
     *
     * @throws Exception
     */
    @Before
    @SuppressWarnings("unchecked")
    public final void prepareTemplateEngineTest() throws Exception {
        // Preparation of test instance
        this.testContextManager.prepareTestInstance(this);

        // Preliminary test assertions
        assertThat(this.templateName, not(isEmptyOrNullString()));
        assertThat(this.contextName, not(isEmptyOrNullString()));

        this.context = this.applicationContext.getBean(this.contextName, Map.class);

        assertThat(this.context, is(not(nullValue())));
        assertThat(this.context.entrySet(), is(not(empty())));
    }

    /**
     * Test method for {@link TemplateEngine#process(String, Object)}.
     *
     * @throws Exception
     */
    @Test
    public final void testTemplateCompilation() throws Exception {
        this.doTestTemplateCompilation();
    }

    /**
     * Actual test assertions and matching.
     *
     * @throws IOException
     */
    protected abstract void doTestTemplateCompilation() throws IOException;

    /**
     * Returns the result of template {@link #templateName} compilation, using the defined {@link #context}.<br />
     * In other words the <em>compiled</em> template is returned.
     *
     * @return the result of template {@link #templateName} compilation, using the defined {@link #context}.<br />
     *         In other words the <em>compiled</em> template is returned
     * @throws IOException
     */
    protected final String processTemplate() throws IOException {
        return this.templateEngine.process(this.templateName, this.context);
    }

    /**
     * @return the context
     */
    protected final Map<String, Object> getContext() {
        return this.context;
    }

}
