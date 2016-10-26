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
package org.geoserver.security.iride.util.factory.security;

import org.geoserver.security.iride.IrideRoleService;
import org.geoserver.security.iride.service.IrideService;
import org.geoserver.security.iride.util.factory.AbstractFactory;

/**
 * {@link IrideRoleService} Factory.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public final class IrideRoleServiceFactory extends AbstractFactory<IrideRoleService> {

    /**
     * <code>IRIDE</code> service "policies" enforcer instance.
     */
    private IrideService irideService;

    /**
     * Constructor.
     */
    public IrideRoleServiceFactory() {
        /* NOP */
    }

    /**
     * Constructor.
     *
     * @param irideService <code>IRIDE</code> service "policies" enforcer instance
     */
    public IrideRoleServiceFactory(IrideService irideService) {
        this.irideService = irideService;
    }

    /**
     * Get the <code>IRIDE</code> service "policies" enforcer instance.
     *
     * @return the <code>IRIDE</code> service "policies" enforcer instance
     */
    public IrideService getIrideService() {
        return this.irideService;
    }

    /**
     * Set the <code>IRIDE</code> service "policies" enforcer instance.
     *
     * @param irideService the <code>IRIDE</code> service "policies" enforcer instance
     */
    public void setIrideService(IrideService irideService) {
        this.irideService = irideService;
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.iride.util.factory.AbstractFactory#newInstance()
     */
    @Override
    protected final IrideRoleService newInstance() {
        final IrideRoleService irideRoleService = new IrideRoleService();

        // Set the Policy Manager
        irideRoleService.setIrideService(this.irideService);

        return irideRoleService;
    }

}
