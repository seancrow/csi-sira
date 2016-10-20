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
package org.geoserver.security.iride.util.xml.transform;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import javax.xml.transform.Source;
import javax.xml.transform.TransformerException;

import org.apache.commons.lang.StringUtils;
import org.geoserver.security.iride.AbstractXmlUnitTest;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestContextManager;

/**
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
@RunWith(Parameterized.class)
public abstract class AbstractXslProcessorTest extends AbstractXmlUnitTest {

    private static final String XSL_SUFFIX = "XSL";

    private static final String XML_SUFFIX = "XML";

    private static final String RESULT_SUFFIX = "RES";

    private final TestContextManager testContextManager;

    private final String xslSourceName;

    private final String xmlSourceName;

    private final String expectedResultName;

    private Source xslSource;

    private Source xmlSource;

    private String expectedResult;

    @Autowired
    private ApplicationContext applicationContext;

    /**
     * <a href="https://en.wikipedia.org/wiki/XSLT"><code>XSL</code> transformation</a> xmlTransformer.
     */
    @Autowired
    private XmlTransformer xmlTransformer;

    /**
     * Constructor.
     *
     * @param xslSourceName
     * @param xmlSourceName
     */
    protected AbstractXslProcessorTest(String xslSourceName, String xmlSourceName) {
        this(xslSourceName, xmlSourceName, null);
    }

    /**
     * Constructor.
     *
     * @param xslSourceName
     * @param xmlSourceName
     * @param expectedResultName
     */
    protected AbstractXslProcessorTest(String xslSourceName, String xmlSourceName, String expectedResultName) {
        this.testContextManager = new TestContextManager(this.getClass());

        this.xslSourceName = xslSourceName;
        this.xmlSourceName = xmlSourceName;

        this.expectedResultName = expectedResultName;
    }

    /**
     * {@link XmlTransformer} test preparation and setup.
     *
     * @throws Exception
     */
    @Before
    public final void setUp() throws Exception {
        // Preparation of test instance
        this.testContextManager.prepareTestInstance(this);

        this.xslSource = this.applicationContext.getBean(this.xslSourceName + XSL_SUFFIX, Source.class);
        this.xmlSource = this.applicationContext.getBean(this.xmlSourceName + XML_SUFFIX, Source.class);

        if (StringUtils.isNotBlank(this.expectedResultName)) {
            this.expectedResult = this.applicationContext.getBean(this.expectedResultName + RESULT_SUFFIX, String.class);
        }

        // Preliminary test assertions
        assertThat(this.xslSource, not(nullValue()));
        assertThat(this.xslSource.getSystemId(), not(isEmptyOrNullString()));
        assertThat(this.xmlSource, not(nullValue()));
        assertThat(this.xmlSource.getSystemId(), not(isEmptyOrNullString()));
    }

    /**
     * Test method. It should be overridden by subclasses and properly annotated.
     *
     * @throws XmlTransformerException
     */
    public abstract void testXslProcessing() throws TransformerException;

    /**
     * Returns the result of <code>XSL</code> processing,
     * transforming the given <code>XML</code> {@link #xmlSourceName} with the given <code>XSL</code> {@link #xslSourceName}.
     *
     * @return the result of the <code>XSL</code> processing,
     *         transforming the given <code>XML</code> {@link #xmlSourceName} with the given <code>XSL</code> {@link #xslSourceName}
     * @throws XmlTransformerException
     * @see {@link XmlTransformer#transform(Source, Source, javax.xml.transform.Result, boolean)}
     */
    protected String transform() throws TransformerException {
        final StringResult result = XmlTransformer.newStreamResult();

        this.xmlTransformer.transform(this.xslSource, this.xmlSource, result, true);

        return result.toString();
    }

    /**
     * Actual <code>JUnit</code> Test <code>XSL</code> processing.
     * <p>It should return the result of the <code>XSL</code> processing, by {@link #transform()}.
     *
     * @return the result of the <code>XSL</code> processing, by {@link #transform()}
     * @throws XmlTransformerException
     */
    protected abstract String doTestXslProcessing() throws TransformerException;

    /**
     * @return the xslSource
     */
    protected final Source getXslSource() {
        return this.xslSource;
    }

    /**
     * @return the xmlSource
     */
    protected final Source getXmlSource() {
        return this.xmlSource;
    }

    /**
     * @return the expectedResult
     */
    protected final String getExpectedResult() {
        return this.expectedResult;
    }

    /**
     * @return the xmlTransformer
     */
    protected final XmlTransformer getProcessor() {
        return this.xmlTransformer;
    }

}
