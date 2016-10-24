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
import org.geoserver.security.iride.service.policy.handler.IridePolicyResponseHandler;
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
     * Registry for available <code>IRIDE</code> service "policy" <em>request</em> handlers.
     */
    private IridePolicyRegistry<IridePolicyRequestHandler> policyRequestHandlers;

    /**
     * Registry for available <code>IRIDE</code> service "policy" <em>response</em> handlers.
     */
    private IridePolicyRegistry<IridePolicyResponseHandler> policyResponseHandlers;

    /**
     * Constructor.
     */
    public IridePolicyManager() {
        this(new IridePolicyRegistry<IridePolicyRequestHandler>(), new IridePolicyRegistry<IridePolicyResponseHandler>());
    }

    /**
     * Constructor.
     *
     * @param policyRequestHandlers registry for available <code>IRIDE</code> service "policy" <em>request</em> handlers
     * @param policyResponseHandlers registry for available <code>IRIDE</code> service "policy" <em>response</em> handlers
     */
    public IridePolicyManager(IridePolicyRegistry<IridePolicyRequestHandler> policyRequestHandlers, IridePolicyRegistry<IridePolicyResponseHandler> policyResponseHandlers) {
        this.setPolicyRequestHandlers(policyRequestHandlers);
        this.setPolicyResponseHandlers(policyResponseHandlers);
    }

    /**
     * Returns {@code true} if the given "policy" handler is contained by this registry:
     * i.e. an <code>IRIDE</code> service "policy" <em>request</em> handler is indexed by the given policy,
     * {@code false} otherwise.
     *
     * @param policy the given "policy"
     * @return {@code true} if the given "policy" <em>request</em> handler is contained by this registry:
     *         i.e. an <code>IRIDE</code> service "policy" <em>request</em> handler is indexed by the given policy,
     *         {@code false} otherwise
     */
    public boolean hasPolicyRequestHandler(IridePolicy policy) {
        return this.getPolicyRequestHandlers().contains(policy);
    }

    /**
     * Get the registered <code>IRIDE</code> service "policy" <em>request</em> handler indexed by the given policy,
     * or {@code null} if no <code>IRIDE</code> service "policy" <em>request</em> handler is found for the the given policy.
     *
     * @param policy the given "policy"
     * @return the registered <code>IRIDE</code> service "policy" <em>request</em> handler indexed by the given policy,
     *         or {@code null} if no <code>IRIDE</code> service "policy" <em>request</em> handler is found for the the given policy
     */
    public IridePolicyRequestHandler getPolicyRequestHandler(IridePolicy policy) {
        final IridePolicyRequestHandler policyRequestHandler = this.getPolicyRequestHandlers().lookup(policy);

        LOGGER.finer(String.format("Request Handler for IRIDE Policy '%s' found: %b", policy.getServiceName(), policyRequestHandler != null));

        return policyRequestHandler;
    }

    /**
     * Get the registry for available <code>IRIDE</code> service "policy" <em>request</em> handlers.
     *
     * @return the registry for available <code>IRIDE</code> service "policy" <em>request</em> handlers
     */
    public IridePolicyRegistry<IridePolicyRequestHandler> getPolicyRequestHandlers() {
        return this.policyRequestHandlers;
    }

    /**
     * Set the registry for available <code>IRIDE</code> service "policy" <em>request</em> handlers.
     *
     * @param policyRequestHandlers the registry for available <code>IRIDE</code> service "policy" <em>request</em> handlers
     */
    public void setPolicyRequestHandlers(IridePolicyRegistry<IridePolicyRequestHandler> policyRequestHandlers) {
        this.policyRequestHandlers  = policyRequestHandlers == null
            ? new IridePolicyRegistry<IridePolicyRequestHandler>()
            : policyRequestHandlers;
    }

    /**
     * Returns {@code true} if the given "policy" handler is contained by this registry:
     * i.e. an <code>IRIDE</code> service "policy" <em>response</em> handler is indexed by the given policy,
     * {@code false} otherwise.
     *
     * @param policy the given "policy"
     * @return {@code true} if the given "policy" <em>response</em> handler is contained by this registry:
     *         i.e. an <code>IRIDE</code> service "policy" <em>response</em> handler is indexed by the given policy,
     *         {@code false} otherwise
     */
    public boolean hasPolicyResponseHandler(IridePolicy policy) {
        return this.getPolicyRequestHandlers().contains(policy);
    }

    /**
     * Get the registered <code>IRIDE</code> service "policy" <em>response</em> handler indexed by the given policy,
     * or {@code null} if no <code>IRIDE</code> service "policy" <em>response</em> handler is found for the the given policy.
     *
     * @param policy the given "policy"
     * @return the registered <code>IRIDE</code> service "policy" <em>response</em> handler indexed by the given policy,
     *         or {@code null} if no <code>IRIDE</code> service "policy" <em>response</em> handler is found for the the given policy
     */
    public IridePolicyResponseHandler getPolicyResponseHandler(IridePolicy policy) {
        final IridePolicyResponseHandler policyResponseHandler = this.getPolicyResponseHandlers().lookup(policy);

        LOGGER.finer(String.format("Response Handler for IRIDE Policy '%s' found: %b", policy.getServiceName(), policyResponseHandler != null));

        return policyResponseHandler;
    }

    /**
     * Get the registry for available <code>IRIDE</code> service "policy" <em>response</em> handlers.
     *
     * @return the registry for available <code>IRIDE</code> service "policy" <em>response</em> handlerss
     */
    public IridePolicyRegistry<IridePolicyResponseHandler> getPolicyResponseHandlers() {
        return this.policyResponseHandlers;
    }

    /**
     * Set the registry for available <code>IRIDE</code> service "policy" <em>response</em> handlers.
     *
     * @param policyResponseHandlers the registry for available <code>IRIDE</code> service "policy" <em>response</em> handlers
     */
    public void setPolicyResponseHandlers(IridePolicyRegistry<IridePolicyResponseHandler> policyResponseHandlers) {
        this.policyResponseHandlers = policyResponseHandlers == null
            ? new IridePolicyRegistry<IridePolicyResponseHandler>()
            : policyResponseHandlers;
    }

}
