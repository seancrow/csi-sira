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
package org.geoserver.security.iride.service.api;

import org.geoserver.security.iride.entity.IrideApplication;
import org.geoserver.security.iride.entity.IrideIdentity;
import org.geoserver.security.iride.entity.IrideRole;
import org.geoserver.security.iride.entity.IrideUseCase;

/**
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public interface PolicyEnforcerBase {

    /**
     *
     * @param identity
     * @param application
     * @return
     */
    IrideRole[] findRuoliForPersonaInApplication(IrideIdentity identity, IrideApplication application);

    /**
     *
     * @param identity
     * @param useCase
     * @return
     */
    IrideRole[] findRuoliForPersonaInUseCase(IrideIdentity identity, IrideUseCase useCase);

    /**
     *
     * @param identity
     * @param application
     * @return
     */
    IrideUseCase[] findUseCasesForPersonaInApplication(IrideIdentity identity, IrideApplication application);

    /**
     *
     * @param username
     * @param password
     * @return
     */
    IrideIdentity identificaUserPassword(String username, String password);

    /**
     *
     * @param identity
     * @return
     */
    Boolean isIdentitaAutentica(IrideIdentity identity);

    /**
     *
     * @param identity
     * @param useCase
     * @return
     */
    Boolean isPersonaAutorizzataInUseCase(IrideIdentity identity, IrideUseCase useCase);

    /**
     *
     * @param identity
     * @param role
     * @return
     */
    Boolean isPersonaInRuolo(IrideIdentity identity, IrideRole role);

    /**
     *
     * @param identity
     * @param useCase
     * @return
     */
    String getInfoPersonaInUseCase(IrideIdentity identity, IrideUseCase useCase);

    /**
     *
     * @param role
     * @return
     */
    String getInfoPersonaSchema(IrideRole role);

}
