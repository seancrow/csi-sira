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
import java.util.logging.Logger;

import org.geoserver.config.GeoServerDataDirectory;
import org.geoserver.platform.GeoServerResourceLoader;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.impl.GeoServerUser;
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
 * <code>GeoServer</code> users/groups security service, backed by <a href="http://www.csipiemonte.it/">CSI</a> <code>IRIDE</code> service <code>JUnit</code> Test.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {
    "classpath:/testContext.xml",
})
@TestExecutionListeners({ DependencyInjectionTestExecutionListener.class })
public final class IrideUserGroupServiceTest {

    /**
     * Logger.
     */
    private static final Logger LOGGER = Logging.getLogger(IrideRoleServiceTest.class);

    private static final String SAMPLE_USER_WITH_NO_ROLES = "AAAAAA00A11M000U/CSI PIEMONTE/DEMO 32/IPA/20161027103359/2/uQ4hHIMEEruA6DGThS3EuA==";

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

        this.irideUserGroupServiceFactory.setSecurityManager(
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

    // TODO: implement other tests

    /**
     * Test method for {@link org.geoserver.security.iride.IrideUserGroupService#canCreateStore()}.
     *
     * @throws IOException
     */
    @Test
    public void testCannotCreateStore() throws IOException {
        LOGGER.entering(this.getClass().getName(), "testCannotCreateStore");

        assertThat(false, is(this.createUserGroupService().canCreateStore()));

        LOGGER.exiting(this.getClass().getName(), "testCannotCreateStore");
    }

    /**
     * Test method for {@link org.geoserver.security.iride.IrideUserGroupService#canCreateStore()}.
     *
     * @throws IOException
     */
    @Test
    public void testCreateStoreReturnsNull() throws IOException {
        LOGGER.entering(this.getClass().getName(), "testCreateStoreReturnsNull");

        assertThat(this.createUserGroupService().createStore(), is(nullValue()));

        LOGGER.exiting(this.getClass().getName(), "testCreateStoreReturnsNull");
    }

    /**
     * Test method for {@link org.geoserver.security.iride.IrideUserGroupService#createGroupObject(String, boolean)}.
     *
     * @throws IOException
     */
    @Test
    public void testCreateUserObjectSpecializedForIride() throws IOException {
        LOGGER.entering(this.getClass().getName(), "testCreateUserObjectSpecializedForIride");

        final String password = "xyz";
        final boolean isEnabled = true;

        final GeoServerUser user = this.createUserGroupService().createUserObject(SAMPLE_USER_WITH_NO_ROLES, password, isEnabled);

        LOGGER.info("User: " + user);

        assertThat(user, instanceOf(IrideGeoServerUser.class));
        assertThat(user.getUsername(), is(SAMPLE_USER_WITH_NO_ROLES));
        assertThat(user.getPassword(), is(password));
        assertThat(user.isEnabled(), is(isEnabled));

        LOGGER.exiting(this.getClass().getName(), "testCreateUserObjectSpecializedForIride");
    }

    /**
     * Test method for {@link org.geoserver.security.iride.IrideUserGroupService#getUserByUsername(String)}.
     *
     * @throws IOException
     */
    @Test(expected = IllegalArgumentException.class)
    public void testGetUserByUsernameForSampleUserWithInvalidServerURL() throws IOException {
        LOGGER.entering(this.getClass().getName(), "testGetUserByUsernameForSampleUserWithInvalidServerURL", new Object[] {SAMPLE_USER_WITH_NO_ROLES, this.config});

        this.config.setServerURL(null);

        try {
            final GeoServerUser user = this.createUserGroupService().getUserByUsername(SAMPLE_USER_WITH_NO_ROLES);

            assertThat(user, is(nullValue()));
        } finally {
            LOGGER.exiting(this.getClass().getName(), "testGetUserByUsernameForSampleUserWithInvalidServerURL");
        }
    }

    /**
     * @param string
     * @return
     * @throws IOException
     */
    private IrideUserGroupService createUserGroupService() throws IOException {
        return (IrideUserGroupService) this.securityProvider.createUserGroupService(this.config);
    }

}
