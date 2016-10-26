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
package org.geoserver.security.iride.util.logging;

import static org.geoserver.security.iride.util.Constants.LOGGER_BASE_NAME;

import java.util.logging.Logger;

import org.geoserver.security.iride.service.api.PolicyEnforcerBase;
import org.geoserver.security.iride.service.api.PolicyEnforcerHelper;
import org.geotools.util.logging.Logging;

/**
 * Provider for various application "layers" {@link Logger}s.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public enum LoggerProvider {

    /**
     * {@link Logger} used by all <a href="http://docs.geoserver.org/latest/en/developer/programming-guide/security/index.html#security-services">Security Services</a>.
     */
    SECURITY(
        Logging.getLogger(LOGGER_BASE_NAME + ".security")
    ),
    /**
     * {@link Logger} used by all <code>IRIDE</code> entities (and related) objects.
     */
    ENTITY(
        Logging.getLogger(LOGGER_BASE_NAME + ".entity")
    ),
    /**
     * {@link Logger} used by {@link PolicyEnforcerBase} and {@link PolicyEnforcerHelper} instances.
     */
    POLICY(
        Logging.getLogger(LOGGER_BASE_NAME + ".policy")
    ),
    /**
     * {@link Logger} used by utility and/or helper classes.
     */
    UTIL(
        Logging.getLogger(LOGGER_BASE_NAME + ".util")
    ),
    ;

    /**
     * {@link Logger} for a specific application "layer".
     */
    private Logger logger;

    /**
     * Constructor.
     *
     * @param logger {@link Logger} for a specific application "layer"
     */
    private LoggerProvider(Logger logger) {
        this.logger = logger;
    }

    /**
     * Return the {@link Logger} for a specific application "layer".
     *
     * @return {@link Logger} for a specific application "layer"
     */
    public Logger getLogger() {
        return this.logger;
    }
}
