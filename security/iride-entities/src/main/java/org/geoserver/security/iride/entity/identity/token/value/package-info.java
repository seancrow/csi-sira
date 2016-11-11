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
/**
 * <code>IRIDE</code> <code>Digital Identity</code> token value and related classes.
 * <p> The token value class models the current value of a particular
 * <code>IRIDE</code> <code>Digital Identity</code> token ({@link org.geoserver.security.iride.entity.identity.token.value.IrideIdentityTokenValue})
 * <p>Related classes let describe the missing ({@link org.geoserver.security.iride.entity.identity.token.value.IrideIdentityMissingTokenValue}
 * and invalid ({@link org.geoserver.security.iride.entity.identity.token.value.IrideIdentityInvalidTokenValue}) token(s),
 * disclosed during <code>IRIDE</code> <code>Digital Identity</code> tokenization (by {@link org.geoserver.security.iride.entity.identity.IrideIdentityTokenizer} class)
 * and validation (by {@link org.geoserver.security.iride.entity.identity.IrideIdentityValidator} class) operations.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
package org.geoserver.security.iride.entity.identity.token.value;