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

import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.lang.StringUtils;
import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.GeoServerUserGroupStore;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.impl.AbstractUserGroupService;
import org.geoserver.security.impl.GeoServerUser;
import org.geoserver.security.iride.config.IrideSecurityServiceConfig;
import org.geoserver.security.iride.entity.IrideApplication;
import org.geoserver.security.iride.entity.IrideIdentity;
import org.geoserver.security.iride.entity.IrideInfoPersona;
import org.geoserver.security.iride.entity.IrideUseCase;
import org.geoserver.security.iride.service.IrideService;
import org.geoserver.security.iride.util.logging.LoggerProvider;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;

/**
 * <code>GeoServer</code> user group security service, backed by <a href="http://www.csipiemonte.it/">CSI</a> <code>IRIDE</code> service.
 * <p><code>IRIDE</code> user group security service is <em>read-only</em>, therefore <em>there is no support for {@link GeoServerUserGroupStore} usage</em>:
 * {@link #canCreateStore()} will return {@code false} and {@link #createStore()} will return {@code null}.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public class IrideUserGroupService extends AbstractUserGroupService implements GeoServerUserGroupService {

    /**
     * Logger.
     */
    private static final Logger LOGGER = LoggerProvider.SECURITY.getLogger();

    /**
     * <code>GeoServer</code> user property for associated {@link IrideIdentity} instance.
     */
    private static final String USER_PROPERTY_IRIDE_IDENTITY = "irideIdentity";

    /**
     * <code>GeoServer</code> user property for associated {@link IrideInfoPersona} instances, if any, expressed as a list.
     * <p>An empty list property in the case there are no associated {@link IrideInfoPersona} instances.
     * <p>Whichever the case, the list is <em>immutable</em>.
     *
     * @see ImmutableList
     */
    private static final String USER_PROPERTY_INFO_PERSONAE = "irideInfoPersonae";

    /**
     * {@link IrideUserGroupService} configuration object.
     */
    private Config config;

    /**
     * <code>IRIDE</code> service "policies" enforcer instance.
     */
    private IrideService irideService;

    /**
     * @return the irideService
     */
    public IrideService getIrideService() {
        return this.irideService;
    }

    /**
     * @param irideService the irideService to set
     */
    public void setIrideService(IrideService irideService) {
        this.irideService = irideService;
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.impl.AbstractGeoServerSecurityService#initializeFromConfig(org.geoserver.security.config.SecurityNamedServiceConfig)
     */
    @Override
    public void initializeFromConfig(SecurityNamedServiceConfig config) throws IOException {
        LOGGER.log(Level.INFO,
            "Initializing {0} with configuration object: \n\t {1}",
            new Object[] { this.getClass().getSimpleName(), config }
        );

        this.name   = config.getName();
        this.config = new Config(config);

        this.getIrideService().initializeFromConfig(config);
    }

    /*
     * E' il "main" per eseguire l'autenticazione via IRIDE.
     *  -> richiamare servizi per verificare IrideIdentity
     *  ->      //      //    per recuperare IrideInfoPersona(s)
     *  -> "assemblare" informazioni su istanza GeoServerUser
     */
    /*
     *
     * (non-Javadoc)
     * @see org.geoserver.security.impl.AbstractUserGroupService#getUserByUsername(java.lang.String)
     */
    @Override
    public GeoServerUser getUserByUsername(String username) throws IOException {
        LOGGER.info("User: " + username);

        GeoServerUser user = null;

        final IrideIdentity irideIdentity = IrideIdentity.parseIrideIdentity(username);
        if (irideIdentity == null) {
            // Houston? We have a problem...
        } else {
            // A formallly valid IRIDE digital identity was given: collect the InfoPersona instances, if any
            final IrideUseCase[] irideUseCases = this.getIrideService().findUseCasesForPersonaInApplication(
                irideIdentity,
                new IrideApplication(this.config.applicationName)
            );

            final List<IrideInfoPersona> infoPersonae = Lists.newArrayList();
            IrideInfoPersona infoPersona;
            for (final IrideUseCase irideUseCase : irideUseCases) {
                infoPersona = this.getIrideService().getInfoPersonaInUseCase(irideIdentity, irideUseCase);
                if (infoPersona != null) {
                    infoPersonae.add(infoPersona);
                }
            }

            user = this.createUserObject(username, null, true);
            user.getProperties().put(USER_PROPERTY_IRIDE_IDENTITY, irideIdentity);
            user.getProperties().put(USER_PROPERTY_INFO_PERSONAE, ImmutableList.copyOf(infoPersonae));
        }

        LOGGER.info("Retrieved User: " + user);

        return user;
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.GeoserverUserGroupService#createUserObject(java.lang.String, java.lang.String, boolean)
     */
    @Override
    public GeoServerUser createUserObject(String username, String password, boolean isEnabled) throws IOException {
       final GeoServerUser user = new IrideGeoServerUser(username);
       user.setEnabled(isEnabled);
       user.setPassword(password);

       return user;
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.impl.AbstractUserGroupService#deserialize()
     */
    @Override
    protected void deserialize() throws IOException {
        /* NOP */
    }

    /**
     * {@link IrideUserGroupService} configuration.
     *
     * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
     */
    private static final class Config {

        /**
         * Application name requesting <code>IRIDE</code> service.
         */
        private final String applicationName;

        /**
         * Constructor.
         *
         * Initialize a {@link Config} object from a {@link SecurityNamedServiceConfig} instance.
         *
         * @param cfg a {@link SecurityNamedServiceConfig} instance
         * @throws IllegalStateException if the {@link #applicationName} is not deemed valid:
         *                               valid {@link #applicationName} must be <em>non-empty</em>,
         *                               as per {@link StringUtils#isNotBlank(String)} check rules.
         */
        Config(SecurityNamedServiceConfig cfg) {
            if (! (cfg instanceof IrideSecurityServiceConfig)) {
                throw new IllegalArgumentException("Config object must be of IrideSecurityServiceConfig type");
            }

            final IrideSecurityServiceConfig irideCfg = (IrideSecurityServiceConfig) cfg;

            this.applicationName = irideCfg.getApplicationName();

            Preconditions.checkState(StringUtils.isNotBlank(this.applicationName), "Application name must not be of an empty string");
        }

    }

}
