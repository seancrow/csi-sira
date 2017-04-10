package it.geosolutions.geoserver.sira.security;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import org.apache.commons.io.IOUtils;
import org.geoserver.data.test.SystemTestData;
import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.AccessMode;
import org.geoserver.security.impl.GeoServerRole;
import org.geoserver.security.impl.GeoServerUser;
import org.geoserver.security.iride.entity.IrideIdentity;
import org.geoserver.security.iride.entity.IrideInfoPersona;
import org.geoserver.security.iride.entity.IrideRole;
import org.geoserver.security.iride.util.IrideUserProperties;
import org.geoserver.test.AbstractAppSchemaTestSupport;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;

import com.google.common.collect.ImmutableSet;
import com.thoughtworks.xstream.XStream;

import it.geosolutions.geoserver.sira.security.config.Rule;
import it.geosolutions.geoserver.sira.security.config.SiraAccessManagerConfigurator;
import it.geosolutions.geoserver.sira.security.expression.ExpressionRuleEngine;
import it.geosolutions.geoserver.sira.security.util.factory.expression.ExpressionRuleEngineFactory;

public class SiraInfoPersonaTest extends AbstractAppSchemaTestSupport {
    private static final String CONFIG_RESOURCE = "/test-iride-sira-access-manager-config.xml";
    private static final String CONFIG_FILE_DEST = "sira-access-manager.xml";

    private static final IrideIdentity DEMO_32 = IrideIdentity.parseIrideIdentity("AAAAAA00A11M000U/CSI PIEMONTE/DEMO 32/IPA/20161027103359/2/uQ4hHIMEEruA6DGThS3EuA==");
    private static final String PA_GEN_DECSIRA  = "PA_GEN_DECSIRA@REG_PMN";

    private ExpressionRuleEngine expressionRuleEngine;
    private XStream xstream;
    private Properties props;
    
    @Before
    public void setUp() throws NoSuchMethodException, SecurityException {
        final SimpleDateFormat dateFormatter = new SimpleDateFormat("HH:mm:ss a");
        final String now = dateFormatter.format(new Date());

        this.props = new Properties();
        this.props.put("now", now);

        assertThat(ExpressionRuleEngine.getTemplateExpression().getExpressionPrefix(), is("#{"));
        assertThat(ExpressionRuleEngine.getTemplateExpression().getExpressionSuffix(), is("}"));

        this.expressionRuleEngine     = ExpressionRuleEngineFactory.createExpressionRuleEngine(this.props);

        this.xstream = SiraAccessManagerConfigurator.buildXStream();
    }

    @Override
    protected SiraSecurityTestData createTestData() {
        return new SiraSecurityTestData();
    }

    @Override
    protected List<javax.servlet.Filter> getFilters() {
        return Collections.singletonList((javax.servlet.Filter) GeoServerExtensions.bean("filterChainProxy"));
    }

    @Override
    protected void setUpTestData(SystemTestData testData) throws Exception {
        super.setUpTestData(testData);

        this.copyConfigurationFile(testData.getDataDirectoryRoot(), CONFIG_RESOURCE);
    }

    @Override
    protected void onSetUp(SystemTestData testData) throws Exception {
        super.onSetUp(testData);
        this.addUser("DEMO 32", "PIEMONTE", null, Arrays.asList(PA_GEN_DECSIRA));

        final GeoServerUser demo32 = this.getSecurityManager().loadUserGroupService("default").getUserByUsername("DEMO 32");
        demo32.getProperties().put(IrideUserProperties.IRIDE_IDENTITY, DEMO_32);
    }

    @Test
	public void testHasAuthority() {
        final String xml = "<Rule>"
                         + "    <roles>ADMIN</roles>"
                         + "    <workspace>*</workspace>"
                         + "    <layer>*</layer>"
                         + "    <accessMode>#{#if(#hasAuthority('PA_GEN_DECSIRA', '6'), 'READ', 'IGNORERULE')}</accessMode>"
                         + "    <filter>INCLUDE</filter>"
                         + "    <hiddenAttributes />"
                         + "</Rule>";

        final Rule r = (Rule) this.xstream.fromXML(xml);

        Properties properties1 = new Properties();
        properties1.put("ID_AUTORITA", "6");
        IrideInfoPersona ip1 = new IrideInfoPersona(IrideRole.parseRole(PA_GEN_DECSIRA), properties1);

        this.login("DEMO 32", "PIEMONTE", new String[] { PA_GEN_DECSIRA }, DEMO_32, ImmutableSet.<IrideInfoPersona>of(ip1));
        final AccessMode accessMode = this.expressionRuleEngine.evaluateAccessMode(r);
        assertThat(accessMode, is(AccessMode.READ));
    }

    @Test
	public void testHasIstatProvincia() {
        final String xml = "<Rule>"
                         + "    <roles>ADMIN</roles>"
                         + "    <workspace>*</workspace>"
                         + "    <layer>*</layer>"
                         + "    <accessMode>#{#if(#hasIstatProvincia('PA_GEN_DECSIRA', '001'), 'READ', 'IGNORERULE')}</accessMode>"
                         + "    <filter>INCLUDE</filter>"
                         + "    <hiddenAttributes />"
                         + "</Rule>";

        final Rule r = (Rule) this.xstream.fromXML(xml);

        Properties properties1 = new Properties();
        properties1.put("ISTAT_PROVINCIA", "001");
        IrideInfoPersona ip1 = new IrideInfoPersona(IrideRole.parseRole(PA_GEN_DECSIRA), properties1);

        this.login("DEMO 32", "PIEMONTE", new String[] { PA_GEN_DECSIRA }, DEMO_32, ImmutableSet.<IrideInfoPersona>of(ip1));
        final AccessMode accessMode = this.expressionRuleEngine.evaluateAccessMode(r);
        assertThat(accessMode, is(AccessMode.READ));
    }

    @Test
	public void testHasIstatComune() {
        final String xml = "<Rule>"
                         + "    <roles>ADMIN</roles>"
                         + "    <workspace>*</workspace>"
                         + "    <layer>*</layer>"
                         + "    <accessMode>#{#if(#hasIstatComune('PA_GEN_DECSIRA', '001272'), 'READ', 'IGNORERULE')}</accessMode>"
                         + "    <filter>INCLUDE</filter>"
                         + "    <hiddenAttributes />"
                         + "</Rule>";

        final Rule r = (Rule) this.xstream.fromXML(xml);

        Properties properties1 = new Properties();
        properties1.put("ISTAT_COMUNE", "001272");
        IrideInfoPersona ip1 = new IrideInfoPersona(IrideRole.parseRole(PA_GEN_DECSIRA), properties1);

        this.login("DEMO 32", "PIEMONTE", new String[] { PA_GEN_DECSIRA }, DEMO_32, ImmutableSet.<IrideInfoPersona>of(ip1));
        final AccessMode accessMode = this.expressionRuleEngine.evaluateAccessMode(r);
        assertThat(accessMode, is(AccessMode.READ));
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
