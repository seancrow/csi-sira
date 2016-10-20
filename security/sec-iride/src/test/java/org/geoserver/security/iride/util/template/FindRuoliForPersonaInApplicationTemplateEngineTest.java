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
import java.util.Arrays;
import java.util.Collection;

import org.geoserver.security.iride.entity.IrideApplication;
import org.geoserver.security.iride.entity.IrideIdentity;
import org.junit.runners.Parameterized.Parameters;

/**
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public final class FindRuoliForPersonaInApplicationTemplateEngineTest extends AbstractTemplateEngineTest {

    /**
     * Constructor.
     *
     * @param templateName
     * @param contextBeanName
     */
    public FindRuoliForPersonaInApplicationTemplateEngineTest(String templateName, String contextBeanName) {
        super(templateName, contextBeanName);
    }

    @Parameters(name = "Processing {0} template, with {1} Spring Bean context")
    public static Collection<String[]> parameters() {
        return Arrays.asList(
            new String[][] {
                {"findRuoliForPersonaInApplication", "irideIdentityAndApplication"},
            }
        );
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.iride.util.template.AbstractTemplateEngineTest#doTestTemplateCompilation()
     */
    @Override
    protected void doTestTemplateCompilation() throws IOException {
        final String result = this.processTemplate();

        assertThat(result, not(isEmptyOrNullString()));

        final IrideIdentity irideIdentity = (IrideIdentity) this.getContext().get("irideIdentity");

        assertThat(result, hasXPath("/soapenv:Envelope/soapenv:Body/int:findRuoliForPersonaInApplication/in0/codFiscale", equalTo(irideIdentity.getCodFiscale())));
        assertThat(result, hasXPath("/soapenv:Envelope/soapenv:Body/int:findRuoliForPersonaInApplication/in0/nome", equalTo(irideIdentity.getNome())));
        assertThat(result, hasXPath("/soapenv:Envelope/soapenv:Body/int:findRuoliForPersonaInApplication/in0/cognome", equalTo(irideIdentity.getCognome())));
        assertThat(result, hasXPath("/soapenv:Envelope/soapenv:Body/int:findRuoliForPersonaInApplication/in0/idProvider", equalTo(irideIdentity.getIdProvider())));
        assertThat(result, hasXPath("/soapenv:Envelope/soapenv:Body/int:findRuoliForPersonaInApplication/in0/timestamp", equalTo(irideIdentity.getTimestamp())));
        assertThat(result, hasXPath("/soapenv:Envelope/soapenv:Body/int:findRuoliForPersonaInApplication/in0/livelloAutenticazione", equalTo(String.valueOf(irideIdentity.getLivelloAutenticazione()))));
        assertThat(result, hasXPath("/soapenv:Envelope/soapenv:Body/int:findRuoliForPersonaInApplication/in0/mac", equalTo(irideIdentity.getMac())));
        assertThat(result, hasXPath("/soapenv:Envelope/soapenv:Body/int:findRuoliForPersonaInApplication/in0/rappresentazioneInterna", equalTo(irideIdentity.toInternalRepresentation())));

        final IrideApplication application = (IrideApplication) this.getContext().get("application");

        assertThat(result, hasXPath("/soapenv:Envelope/soapenv:Body/int:findRuoliForPersonaInApplication/in1/id", equalTo(application.getId())));
    }

}
