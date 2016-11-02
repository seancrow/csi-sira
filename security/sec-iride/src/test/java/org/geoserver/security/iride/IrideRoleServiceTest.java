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
package org.geoserver.security.iride;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.SortedSet;
import java.util.logging.Logger;

import org.geoserver.config.GeoServerDataDirectory;
import org.geoserver.platform.GeoServerResourceLoader;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.impl.GeoServerRole;
import org.geoserver.security.iride.config.IrideSecurityServiceConfig;
import org.geoserver.security.iride.util.factory.security.IrideRoleServiceFactory;
import org.geoserver.security.iride.util.factory.security.IrideUserGroupServiceFactory;
import org.geotools.util.logging.Logging;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.support.DependencyInjectionTestExecutionListener;

/**
 * <code>GeoServer</code> roles security service, backed by <a href="http://www.csipiemonte.it/">CSI</a> <code>IRIDE</code> service <code>JUnit</code> Test.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {
    "classpath:/testContext.xml",
})
@TestExecutionListeners({ DependencyInjectionTestExecutionListener.class })
public final class IrideRoleServiceTest {

    /**
     * Logger.
     */
    private static final Logger LOGGER = Logging.getLogger(IrideRoleServiceTest.class);

    private static final String SAMPLE_USER_WITH_NO_ROLES = "AAAAAA00A11M000U/CSI PIEMONTE/DEMO 32/IPA/20161027103359/2/uQ4hHIMEEruA6DGThS3EuA==";

    /**
     * A "dummy" {@link GeoServerRole}.
     */
    private static final GeoServerRole DUMMY_ROLE = new GeoServerRole("dummy");

    private File tempFolder;

    /**
     * Factory that creates a new, configured, {@link IrideRoleService} instance.
     */
    @Autowired
    private IrideRoleServiceFactory irideRoleServiceFactory;

    /**
     * Factory that creates a new, configured, {@link IrideRoleService} instance.
     */
    @Autowired
    private IrideUserGroupServiceFactory irideUserGroupServiceFactory;

    private IrideSecurityProvider securityProvider;

    private IrideSecurityServiceConfig config;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {
        this.tempFolder = File.createTempFile("iride", "test");
        this.tempFolder.delete();
        this.tempFolder.mkdirs();

        this.irideRoleServiceFactory.setSecurityManager(
            new GeoServerSecurityManager(
                new GeoServerDataDirectory(
                    new GeoServerResourceLoader(this.tempFolder)
                )
            )
        );
        this.securityProvider = new IrideSecurityProvider(this.irideRoleServiceFactory, this.irideUserGroupServiceFactory);

        this.config = new IrideSecurityServiceConfig();
        this.config.setName("iride");
        this.config.setClassName(IrideRoleService.class.getName());
        this.config.setServerURL("http://local-applogic-nmsf2e.csi.it/pep_wsfad_nmsf_policy/services/PolicyEnforcerBase");
        this.config.setApplicationName("DECSIRA");
        this.config.setAdminRole("SUPUSR_DECSIRA");
        this.config.setFallbackRoleService("default");
    }

    /**
     * @throws java.lang.Exception
     */
    @After
    public void tearDown() throws Exception {
        this.tempFolder.delete();
    }

    /**
     * Test method for {@link org.geoserver.security.iride.IrideRoleService#canCreateStore()}.
     *
     * @throws IOException
     */
    @Test
    public void testCannotCreateStore() throws IOException {
        LOGGER.entering(this.getClass().getName(), "testCannotCreateStore");

        assertThat(false, is(this.createRoleService().canCreateStore()));

        LOGGER.exiting(this.getClass().getName(), "testCannotCreateStore");
    }

    /**
     * Test method for {@link org.geoserver.security.iride.IrideRoleService#canCreateStore()}.
     *
     * @throws IOException
     */
    @Test
    public void testCreateStoreReturnsNull() throws IOException {
        LOGGER.entering(this.getClass().getName(), "testCreateStoreReturnsNull");

        assertThat(this.createRoleService().createStore(), is(nullValue()));

        LOGGER.exiting(this.getClass().getName(), "testCreateStoreReturnsNull");
    }

    /**
     * Test method for {@link org.geoserver.security.iride.IrideRoleService#getRolesForUser(java.lang.String)}.
     *
     * @throws IOException
     */
    @Test(expected = IllegalArgumentException.class)
    public void testGetRolesForSampleUserWithInvalidServerURL() throws IOException {
        LOGGER.entering(this.getClass().getName(), "testGetRolesForSampleUserWithInvalidServerURL", new Object[] {SAMPLE_USER_WITH_NO_ROLES, this.config});

        this.config.setServerURL(null);

        try {
            this.createRoleService().getRolesForUser(SAMPLE_USER_WITH_NO_ROLES);
        } finally {
            LOGGER.exiting(this.getClass().getName(), "testGetRolesForSampleUserWithInvalidServerURL");
        }
    }

    /**
     * Test method for {@link org.geoserver.security.iride.IrideRoleService#getRolesForUser(java.lang.String)}.
     *
     * @throws IOException
     */
    @Test
    public void testGetRolesForSampleUserWithNoRoles() throws IOException {
        LOGGER.entering(this.getClass().getName(), "testGetRolesForSampleUserWithNoRoles", new Object[] {SAMPLE_USER_WITH_NO_ROLES, this.config});

        try {
            final SortedSet<GeoServerRole> roles = this.createRoleService().getRolesForUser(SAMPLE_USER_WITH_NO_ROLES);

            assertThat(roles, not(nullValue()));
            assertThat(roles.size(), is(0));
        } finally {
            LOGGER.exiting(this.getClass().getName(), "testGetRolesForSampleUserWithNoRoles");
        }
    }

    /**
     * Test method for {@link org.geoserver.security.iride.IrideRoleService#getRolesForUser(java.lang.String)}.
     *
     * @throws IOException
     */
    @Test(expected = UnsupportedOperationException.class)
    public void testGetRolesForSampleUserNotModifiable() throws IOException {
        LOGGER.entering(this.getClass().getName(), "testGetRolesForSampleUserNotModifiable", new Object[] {SAMPLE_USER_WITH_NO_ROLES, this.config});

        try {
            final SortedSet<GeoServerRole> roles = this.createRoleService().getRolesForUser(SAMPLE_USER_WITH_NO_ROLES);

            assertThat(roles, not(nullValue()));
            assertThat(roles.size(), is(0));

            // throws UnsupportedOperationException
            roles.add(DUMMY_ROLE);
        } finally {
            LOGGER.exiting(this.getClass().getName(), "testGetRolesForSampleUserNotModifiable");
        }
    }

    /**
     * @param string
     * @return
     * @throws IOException
     */
    private IrideRoleService createRoleService() throws IOException {
        return (IrideRoleService) this.securityProvider.createRoleService(this.config);
    }

}
