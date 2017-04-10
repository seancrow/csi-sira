/*
 *  CSI SIRA - Access Manager Security Module ("Rules Engine"), a GeoServer Secure Catalog Resource Access Manager plugin with which specify advanced rules evaluated to decide what the specified user can access.
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
package it.geosolutions.geoserver.sira.security;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.io.IOUtils;
import org.geoserver.catalog.Catalog;
import org.geoserver.catalog.FeatureTypeInfo;
import org.geoserver.data.test.SystemTestData;
import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.impl.GeoServerRole;
import org.geoserver.security.impl.GeoServerUser;
import org.geoserver.security.iride.entity.IrideIdentity;
import org.geoserver.security.iride.entity.IrideInfoPersona;
import org.geoserver.security.iride.util.IrideUserProperties;
import org.geoserver.test.AbstractAppSchemaTestSupport;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;

import com.google.common.collect.ImmutableSet;

/**
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public class IrideSiraSecurityTest extends AbstractAppSchemaTestSupport {

    private static final String CONFIG_RESOURCE = "/test-iride-sira-access-manager-config.xml";
    private static final String CONFIG_FILE_DEST = "sira-access-manager.xml";

    private static final IrideIdentity DEMO_20 = IrideIdentity.parseIrideIdentity("AAAAAA00B77B000F/CSI PIEMONTE/DEMO 20/IPA/20160531113948/2/1IQssTaf4vNMa66qU52m7g==");
    private static final IrideIdentity DEMO_32 = IrideIdentity.parseIrideIdentity("AAAAAA00A11M000U/CSI PIEMONTE/DEMO 32/IPA/20161027103359/2/uQ4hHIMEEruA6DGThS3EuA==");

    private static final String PA_GEN_DECSIRA  = "PA_GEN_DECSIRA@REG_PMN";
    private static final String PA_SPEC_DECSIRA = "PA_SPEC_DECSIRA@REG_PMN";

    @Test
    public void testSecureDataStore() {
        final Catalog catalog = this.getCatalog();

        // I'm not logged in, nothing should be returned
        FeatureTypeInfo aua = catalog.getFeatureTypeByName("sira:AutorizzazioneUnicaAmbientale");
        assertNull(aua);

        // login as user with role PA_SPEC_DECSIRA
        this.login("DEMO 20", "PIEMONTE", new String[] { PA_SPEC_DECSIRA }, DEMO_20, ImmutableSet.<IrideInfoPersona>of());

        aua = catalog.getFeatureTypeByName("sira:AutorizzazioneUnicaAmbientale");
        assertNotNull(aua);
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.test.AbstractAppSchemaTestSupport#createTestData()
     */
    @Override
    protected SiraSecurityTestData createTestData() {
        return new SiraSecurityTestData();
    }

    /**
     * Enable the Spring Security auth filters
     */
    /*
     * (non-Javadoc)
     * @see org.geoserver.test.GeoServerSystemTestSupport#getFilters()
     */
    @Override
    protected List<javax.servlet.Filter> getFilters() {
        return Collections.singletonList((javax.servlet.Filter) GeoServerExtensions.bean("filterChainProxy"));
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.test.GeoServerSystemTestSupport#setUpTestData(org.geoserver.data.test.SystemTestData)
     */
    @Override
    protected void setUpTestData(SystemTestData testData) throws Exception {
        super.setUpTestData(testData);

        this.copyConfigurationFile(testData.getDataDirectoryRoot(), CONFIG_RESOURCE);
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.test.AbstractAppSchemaTestSupport#onSetUp(org.geoserver.data.test.SystemTestData)
     */
    @Override
    protected void onSetUp(SystemTestData testData) throws Exception {
        super.onSetUp(testData);

        this.addUser("DEMO 20", "PIEMONTE", null, Arrays.asList(PA_SPEC_DECSIRA));

        final GeoServerUser demo20 = this.getSecurityManager().loadUserGroupService("default").getUserByUsername("DEMO 20");
        demo20.getProperties().put(IrideUserProperties.IRIDE_IDENTITY, DEMO_20);

        this.addUser("DEMO 32", "PIEMONTE", null, Arrays.asList(PA_GEN_DECSIRA));

        final GeoServerUser demo32 = this.getSecurityManager().loadUserGroupService("default").getUserByUsername("DEMO 32");
        demo32.getProperties().put(IrideUserProperties.IRIDE_IDENTITY, DEMO_32);
    }

    private void copyConfigurationFile(File dataDirRoot, String configResource) throws IOException {
        // copy configuration to data directory
        assertTrue(dataDirRoot.canWrite());

        final File securityDir = new File(dataDirRoot, "security");
        assertNotNull(securityDir);
        if (! securityDir.exists()) {
            assertTrue(securityDir.mkdir());
        }
        assertTrue(securityDir.canWrite());
        final File configFile = new File(securityDir, CONFIG_FILE_DEST);
        try (final FileOutputStream fos = new FileOutputStream(configFile)) {
            IOUtils.copy(this.getClass().getResourceAsStream(configResource), fos);
        }
        assertTrue(configFile.exists());
    }

    private void login(String username, String password, String[] roles, IrideIdentity identity, Set<IrideInfoPersona> infoPersonae) {
        SecurityContextHolder.setContext(new SecurityContextImpl());

        final Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        for (final String role : roles) {
            authorities.add(new GeoServerRole(role));
        }

        final GeoServerUser user = new GeoServerUser(username);
        user.setAuthorities(authorities);
        user.setPassword(password);
        user.getProperties().put(IrideUserProperties.IRIDE_IDENTITY, identity);
        user.getProperties().put(IrideUserProperties.INFO_PERSONAE, infoPersonae);

        SecurityContextHolder.getContext().setAuthentication(
            new UsernamePasswordAuthenticationToken(user, password, authorities)
        );
    }

}
