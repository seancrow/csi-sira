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
package org.geoserver.security.iride.service.policy;

import java.util.logging.Logger;

import org.geoserver.security.iride.service.policy.handler.IridePolicyRequestHandler;
import org.geoserver.security.iride.util.logging.LoggerProvider;

/**
 * Manager class for <code>IRIDE</code> service "policy" handlers.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public final class IridePolicyManager {

    /**
     * Logger.
     */
    private static final Logger LOGGER = LoggerProvider.POLICY.getLogger();

    /**
     * Registry for available <code>IRIDE</code> service "policy" caller helpers.
     */
    private final IridePolicyRegistry<IridePolicyRequestHandler> policyRequestHandlers;

    /**
     * Constructor.
     *
     * @param policyRequestHandlers registry for available <code>IRIDE</code> service "policy" caller helpers
     */
    public IridePolicyManager(IridePolicyRegistry<IridePolicyRequestHandler> policyRequestHandlers) {
        this.policyRequestHandlers = policyRequestHandlers;
    }

    /**
     *
     * @param policy
     * @return
     */
    public IridePolicyRequestHandler getPolicyRequestHandler(IridePolicy policy) {
        final IridePolicyRequestHandler policyRequestHandler = this.policyRequestHandlers.lookup(policy);

        LOGGER.finer(String.format("Request Handler for IRIDE Policy '%s' found: %b", policy.getServiceName(), policyRequestHandler != null));

        return policyRequestHandler;
    }

}
