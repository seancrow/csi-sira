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

/**
 * Registry class for available <code>IRIDE</code> service "policy" handlers.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 *
 * @param <H>
 */
public final class IridePolicyRegistry<H extends AbstractIridePolicyHandler> {

    /**
     * Logger.
     */
    private static final Logger LOGGER = LoggerProvider.POLICY.getLogger();

    /**
     * Registered available <code>IRIDE</code> service "policy" handler, indexed by their "policy".
     */
    private final Map<IridePolicy, H> policies;

    /**
     * Constructor.
     */
    public IridePolicyRegistry() {
        this.policies = Collections.synchronizedMap(
            new EnumMap<IridePolicy, H>(IridePolicy.class)
        );
    }

    /**
     * Constructor.
     *
     * @param policyCallers registered available <code>IRIDE</code> service "policy" handler, indexed by their "policy"
     */
    public IridePolicyRegistry(H[] policyCallers) {
        this();

        this.register(policyCallers);
    }

    /**
     * Returns {@code true} if the given "policy" is contained by this registry:
     * i.e. an <code>IRIDE</code> service "policy" handler is present for the given policy.
     *
     * @param policy
     * @return
     */
    public boolean contains(IridePolicy policy) {
        return this.policies.containsKey(policy);
    }

    /**
     * Returns a <code>IRIDE</code> service "policy" handler if one iss found registered for the given policy.
     *
     * @param policy
     * @return
     */
    public H lookup(IridePolicy policy) {
        return this.policies.get(policy);
    }

    /**
     *
     * @param policyCallers
     */
    public void register(H[] policyCallers) {
        LOGGER.finer(String.format("Adding %d IRIDE Policy Handlers", policyCallers.length));

        for (final H policyCaller : policyCallers) {
            this.register(policyCaller);
        }
    }

    /**
     *
     * @param policyCaller
     */
    public void register(H policyCaller) {
        this.register(policyCaller.getPolicy(), policyCaller);
    }

    /**
     *
     * @param policy
     * @param policyCaller
     */
    private void register(IridePolicy policy, H policyCaller) {
        this.policies.put(policy, policyCaller);

        LOGGER.finer(String.format("Added Handler for IRIDE Policy '%s'", policy.getServiceName()));
    }

}
