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
package org.geoserver.security.iride.service;

import java.io.IOException;

import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.iride.service.api.PolicyEnforcerBase;

/**
 * <code>IRIDE</code> service interface.
 * <p>This interface act as a facade to the needed <code>IRIDE</code> "policies" enforcer interfaces,
 * adding integration to GeoServer Security Provider.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public interface IrideService extends PolicyEnforcerBase {

    /**
     * Initialize from configuration object
     *
     * @param config
     * @throws IOException
     */
    void initializeFromConfig(SecurityNamedServiceConfig config) throws IOException;

}
