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
package org.geoserver.security.iride.util.factory.template.freemarker.roleservice;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.util.logging.Logger;

import org.geoserver.security.iride.IrideRoleService;
import org.geoserver.security.iride.service.IridePolicyEnforcer;
import org.geoserver.security.iride.service.policy.IridePolicyManager;
import org.geoserver.security.iride.util.factory.security.IrideRoleServiceFactory;
import org.geotools.util.logging.Logging;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.support.DependencyInjectionTestExecutionListener;

/**
 * {@link IrideRoleService} Factory <code>JUnit</code> Test Case.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
@RunWith( SpringJUnit4ClassRunner.class )
@ContextConfiguration(locations = {
    "classpath:/testContext.xml",
})
@TestExecutionListeners({ DependencyInjectionTestExecutionListener.class })
public final class IrideRoleServiceFactoryTest {

    /**
     * Logger.
     */
    private static final Logger LOGGER = Logging.getLogger(IrideRoleServiceFactoryTest.class);

    /**
     * {@link IrideRoleService} Factory.
     */
    @Autowired
    private IrideRoleServiceFactory irideRoleServiceFactory;

    /**
     * <code>IRIDE</code> service "policies" enforcer instance.
     */
    @Autowired
    private IridePolicyEnforcer policyEnforcer;

    /**
     * Test method for {@link org.geoserver.security.iride.util.factory.security.IrideRoleServiceFactory#setPolicyManager(IridePolicyManager)}.
     */
    @Test
    public void testSetIrideRoleServiceFactoryPolicyEnforcer() {
        LOGGER.entering(this.getClass().getName(), "testSetIrideRoleServiceFactoryPolicyManager");
        try {
            assertThat(this.irideRoleServiceFactory.getPolicyEnforcer(), is(nullValue()));

            this.irideRoleServiceFactory.setPolicyEnforcer(this.policyEnforcer);

            assertThat(this.irideRoleServiceFactory.getPolicyEnforcer(), is(not(nullValue())));
        } finally {
            LOGGER.exiting(this.getClass().getName(), "testSetIrideRoleServiceFactoryPolicyManager");
        }
    }

    /**
     * Test method for {@link org.geoserver.security.iride.util.factory.security.IrideRoleServiceFactory#create()}.
     */
    @Test
    public void testIrideRoleServiceFactoryCreate() {
        LOGGER.entering(this.getClass().getName(), "testIrideRoleServiceFactoryCreate");
        try {
            this.irideRoleServiceFactory.setPolicyEnforcer(this.policyEnforcer);

            final IrideRoleService irideRoleService = this.irideRoleServiceFactory.create();

            assertThat(irideRoleService.getPolicyEnforcer(), is(this.policyEnforcer));
        } finally {
            LOGGER.exiting(this.getClass().getName(), "testIrideRoleServiceFactoryCreate");
        }
    }

}
