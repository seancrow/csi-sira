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

import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import java.util.logging.Logger;

import org.geoserver.security.iride.service.policy.handler.AbstractIridePolicyHandler;
import org.geoserver.security.iride.util.logging.LoggerProvider;
import org.geoserver.security.iride.util.object.ObjectRegistry;

/**
 * Registry class for available <code>IRIDE</code> service "policy" handlers.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 *
 * @param <H>
 */
public final class IridePolicyRegistry<H extends AbstractIridePolicyHandler> extends ObjectRegistry<IridePolicy, H> {

    /**
     * Logger.
     */
    private static final Logger LOGGER = LoggerProvider.POLICY.getLogger();

    /**
     * Constructor.
     */
    public IridePolicyRegistry() {
        super();
    }

    /**
     * Constructor.
     *
     * @param policyHandlers <code>IRIDE</code> service "policy" handlers to register
     */
    public IridePolicyRegistry(H[] policyHandlers) {
        super(policyHandlers);
    }

    /**
     * Registers the given <code>IRIDE</code> service "policy" handlers, indexed by theirs policies.
     *
     * @param policyHandlers <code>IRIDE</code> service "policy" handlers to register
     */
    /* (non-Javadoc)
     * @see org.geoserver.security.iride.util.object.ObjectRegistry#register(org.geoserver.security.iride.util.object.RegistrableObject[])
     */
    @Override
    protected void register(H[] policyHandlers) {
        LOGGER.finer(String.format("Adding %d IRIDE Policy Handlers", policyHandlers.length));

        super.register(policyHandlers);
    }

    /**
     * Registers the given <code>IRIDE</code> service "policy" handler, indexed by its policy.
     *
     * @param policyHandler <code>IRIDE</code> service "policy" handler to register
     */
    /*
     * (non-Javadoc)
     * @see org.geoserver.security.iride.util.object.ObjectRegistry#register(org.geoserver.security.iride.util.object.RegistrableObject)
     */
    @Override
    protected void register(H policyHandler) {
        super.register(policyHandler);

        LOGGER.finer(String.format("Added IRIDE Policy Handler '%s'", policyHandler.getObjectId().getServiceName()));
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.iride.util.object.ObjectRegistry#initObjects()
     */
    @Override
    protected Map<IridePolicy, H> initObjects() {
        return Collections.synchronizedMap(
            new EnumMap<IridePolicy, H>(IridePolicy.class)
        );
    }

}
