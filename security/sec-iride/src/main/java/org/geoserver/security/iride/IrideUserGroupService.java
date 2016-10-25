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
import java.util.logging.Level;
import java.util.logging.Logger;

import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.GeoServerUserGroupStore;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.impl.AbstractUserGroupService;
import org.geoserver.security.impl.GeoServerUser;
import org.geoserver.security.iride.util.logging.LoggerProvider;

/**
 * <code>GeoServer</code> user group security service, backed by <a href="http://www.csipiemonte.it/">CSI</a> <code>IRIDE</code> service.
 * <p><em><code>IRIDE</code> user group service is <em>read-only</em>, therefore there is no support for {@link GeoServerUserGroupStore} usage</em>
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public class IrideUserGroupService extends AbstractUserGroupService implements GeoServerUserGroupService {

    /**
     * Logger.
     */
    private static final Logger LOGGER = LoggerProvider.SECURITY.getLogger();

    /**
     * Constructor.
     */
    public IrideUserGroupService() {
        super();
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

        this.name = config.getName();

        // TODO: implement!
        super.initializeFromConfig(config);
    }

    /**
     * <code>IRIDE</code> user group service is <em>read-only</em>, therefore there is no support for {@link GeoServerUserGroupStore}.
     */
    /*
     * (non-Javadoc)
     * @see org.geoserver.security.impl.AbstractGeoServerSecurityService#canCreateStore()
     */
    @Override
    public boolean canCreateStore() {
        return false;
    }

    /*
     * E' il "main" per eseguire l'autenticazione via IRIDE.
     * -> richiamare servizi per verificare IrideIdentity
     * ->      //      //    per recuperare IrideInfoPersona(s)
     * -> "assemblare" informazioni su istanza GeoServerUser
     */
    /*
     *
     * (non-Javadoc)
     * @see org.geoserver.security.impl.AbstractUserGroupService#getUserByUsername(java.lang.String)
     */
    @Override
    public GeoServerUser getUserByUsername(String username) throws IOException {
        // TODO: implement!
        return super.getUserByUsername(username);
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.impl.AbstractUserGroupService#deserialize()
     */
    @Override
    protected void deserialize() throws IOException {
        /* NOP */
    }

}
