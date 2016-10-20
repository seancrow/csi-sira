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
package org.geoserver.security.iride.util.xml.transform.policy;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

import org.geoserver.security.iride.service.policy.IridePolicy;
import org.junit.runners.Parameterized.Parameters;

/**
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public final class IridePolicyResponseXslProcessorTest extends AbstractIridePolicyResponseXslProcessorTest {

    /**
     * Constructor.
     *
     * @param policy
     * @param operationName
     */
    public IridePolicyResponseXslProcessorTest(IridePolicy policy, String operationName) {
        super(policy, operationName);
    }

    /**
     *
     * @return
     * @throws IOException
     */
    @Parameters(name = "Processing {0} response")
    public static Collection<Object[]> parameters() throws IOException {
        return Arrays.asList(
            new Object[][] {
                { IridePolicy.FIND_RUOLI_FOR_PERSONA_IN_APPLICATION, null },
                { IridePolicy.FIND_RUOLI_FOR_PERSONA_IN_USE_CASE, null },
                { IridePolicy.FIND_USE_CASES_FOR_PERSONA_IN_APPLICATION, null },
                { IridePolicy.GET_INFO_PERSONA_IN_USE_CASE, "getInfoPersonaInUseCaseReturn" },
                { IridePolicy.GET_INFO_PERSONA_IN_USE_CASE, null },
                { IridePolicy.IDENTIFICA_USER_PASSWORD, null },
                { IridePolicy.IS_IDENTITA_AUTENTICA, null },
                { IridePolicy.IS_PERSONA_AUTORIZZATA_IN_USE_CASE, null },
                { IridePolicy.IS_PERSONA_AUTORIZZATA_IN_USE_CASE, null },
            }
        );
    }

}
