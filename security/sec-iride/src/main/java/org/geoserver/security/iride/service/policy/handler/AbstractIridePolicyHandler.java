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
package org.geoserver.security.iride.service.policy.handler;

import java.util.logging.Logger;

import org.geoserver.security.iride.service.policy.IridePolicy;
import org.geoserver.security.iride.util.logging.LoggerProvider;
import org.geoserver.security.iride.util.object.RegistrableObject;

/**
 * Base class for <code>IRIDE</code> service "policy" handlers.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public abstract class AbstractIridePolicyHandler implements RegistrableObject<IridePolicy> {

    /**
     * Logger.
     */
    protected static final Logger LOGGER = LoggerProvider.POLICY.getLogger();

    /**
     * The <code>IRIDE</code> service "policy": the specific service operation to handle.
     */
    private final IridePolicy policy;

    /**
     * Constructor.
     *
     * @param policy <code>IRIDE</code> service "policy": the specific service operation to handle
     */
    protected AbstractIridePolicyHandler(IridePolicy policy) {
        this.policy = policy;
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.iride.util.object.RegistrableObject#getObjectId()
     */
    @Override
    public IridePolicy getObjectId() {
        return this.getPolicy();
    }

    /**
     * Get the <code>IRIDE</code> service "policy": the specific service operation to handle.
     *
     * @return the <code>IRIDE</code> service "policy": the specific service operation to handle
     */
    public final IridePolicy getPolicy() {
        return this.policy;
    }

}
