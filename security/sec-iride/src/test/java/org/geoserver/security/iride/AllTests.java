/*
 *  GeoServer Security Provider plugin used for doing authentication and authorization operations using CSI-Piemonte IRIDE Service.
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
package org.geoserver.security.iride;

import org.geoserver.security.iride.util.IrideIdentityValidityTest;
import org.geoserver.security.iride.util.factory.template.freemarker.FreeMarkerConfigurationDefaultFactoryTest;
import org.geoserver.security.iride.util.factory.template.freemarker.FreeMarkerTemplateEngineFactoryTest;
import org.geoserver.security.iride.util.factory.template.freemarker.roleservice.IrideRoleServiceFactoryTest;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

/**
 * Main <code>JUnit</code> Test Suite.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
@RunWith(Suite.class)
@SuiteClasses({
    IrideRoleServiceTest.class,
    IrideIdentityValidityTest.class,
    IrideRoleServiceFactoryTest.class,
    FreeMarkerConfigurationDefaultFactoryTest.class,
    FreeMarkerTemplateEngineFactoryTest.class,
    org.geoserver.security.iride.entity.converter.AllTests.class,
    org.geoserver.security.iride.identity.AllTests.class,
    org.geoserver.security.iride.service.policy.handler.request.AllTests.class,
    org.geoserver.security.iride.soap.request.iride.AllTests.class,
    org.geoserver.security.iride.util.template.AllTests.class,
    org.geoserver.security.iride.util.xml.transform.AllTests.class,
})
public final class AllTests {

    /**
     * Constructor.
     */
    private AllTests() {
        /* NOP */
    }

}
