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
package org.geoserver.security.iride.util.xml.transform.others;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.xml.transform.TransformerException;

import org.junit.Test;
import org.junit.runners.Parameterized.Parameters;

/**
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public final class ErroneousXslProcessorTest extends AbstractOthersXslProcessorTest {

    /**
     * Constructor.
     *
     * @param transformationName
     * @param params
     */
    public ErroneousXslProcessorTest(String transformationName, Map<String, Object> params) {
        super(transformationName, transformationName, transformationName, params);
    }

    /**
     *
     * Parametrize <code>XSL</code>, <em>source</em> <code>XML</code> and <em>target</em> <code>XML</code> name, as well as a bunch of parameters.
     *
     * @return the test parameters
     * @throws IOException
     */
    @Parameters(name = "Processing {0} response")
    public static Collection<Object[]> parameters() throws IOException {
        return Arrays.asList(
            new Object[][] {
                { "erroneousTransformation", new HashMap<String, Object>() {
                        private static final long serialVersionUID = 1L;

                        {
                            this.put("a", "a value");
                            this.put("b", "b value");
                            this.put("c", "c value");
                        }
                    }
                },
                { "erroneousSource", null },
            }
        );
    }

    /**
     * Test method for {@link XmlTransformer#transform(Source, Source, javax.xml.transform.Result, Map, boolean))}.
     *
     * @throws XmlTransformerException
     */
    @Test(expected = TransformerException.class)
    @Override
    public void testXslProcessing() throws TransformerException {
        this.doTestXslProcessing();
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.iride.util.xml.transform.AbstractXslProcessorTest#doTestXslProcessing()
     */
    @Override
    protected String doTestXslProcessing() throws TransformerException {
        final String result = this.transform();

        logger.fine("Transformation result:\n" + result);

        return result;
    }

}
