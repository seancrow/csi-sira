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
package org.geoserver.security.iride;

import org.geoserver.security.impl.GeoServerUser;
import org.springframework.util.StringUtils;

/**
 * <code>IRIDE</code> specialized {@link GeoServerUser}.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public final class IrideGeoServerUser extends GeoServerUser {

    private static final long serialVersionUID = 4174436058680260397L;

    /**
     * Constructor.
     *
     * @param username
     */
    public IrideGeoServerUser(String username) {
        super(username);
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.impl.GeoServerUser#toString()
     */
    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder(StringUtils.trimTrailingWhitespace(super.toString()));
        sb.append("; ").append("User Properties: ").append(this.getProperties());

        return sb.toString();
    }

}
