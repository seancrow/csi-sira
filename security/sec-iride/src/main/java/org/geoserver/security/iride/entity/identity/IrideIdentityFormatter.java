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
package org.geoserver.security.iride.entity.identity;

import org.geoserver.security.iride.entity.IrideIdentity;
import org.geoserver.security.iride.entity.identity.token.IrideIdentityToken;
import org.geoserver.security.iride.util.builder.util.ToStringReflectionBuilder;

/**
 * <code>IRIDE</code> <code>Digital Identity</code> formatter.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public final class IrideIdentityFormatter {

    /**
     * <code>IRIDE</code> <code>Digital Identity</code> entity formatting styles.
     *
     * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
     */
    public enum FormatStyle {

        /**
         * <code>IRIDE</code> <code>Digital Identity</code> internal representation.
         */
        INTERNAL_REPRESENTATION {

            /**
             * Format the given {@link IrideIdentity} instance returning an <code>IRIDE</code> <code>Digital Identity</code> internal representation,
             * with the following format: {@link IrideIdentity#getCodFiscale()} + {@link IrideIdentityToken#SEPARATOR}
             *                            {@link IrideIdentity#getNome()} + {@link IrideIdentityToken#SEPARATOR}
             *                            {@link IrideIdentity#getCognome()} + {@link IrideIdentityToken#SEPARATOR}
             *                            {@link IrideIdentity#getIdProvider()} + {@link IrideIdentityToken#SEPARATOR}
             *                            {@link IrideIdentity#getTimestamp()} + {@link IrideIdentityToken#SEPARATOR}
             *                            {@link IrideIdentity#getLivelloAutenticazione()} + {@link IrideIdentityToken#SEPARATOR}.
             */
            /*
             * (non-Javadoc)
             * @see org.geoserver.security.iride.entity.IrideIdentityFormatter.FormatStyle#format(org.geoserver.security.iride.entity.IrideIdentity)
             */
            @Override
            String format(IrideIdentity irideIdentity) {
                final StringBuilder builder = new StringBuilder();
                builder.append(irideIdentity.getCodFiscale()).append(IrideIdentityToken.SEPARATOR)
                       .append(irideIdentity.getNome()).append(IrideIdentityToken.SEPARATOR)
                       .append(irideIdentity.getCognome()).append(IrideIdentityToken.SEPARATOR)
                       .append(irideIdentity.getIdProvider()).append(IrideIdentityToken.SEPARATOR)
                       .append(irideIdentity.getTimestamp()).append(IrideIdentityToken.SEPARATOR)
                       .append(irideIdentity.getLivelloAutenticazione());

                return builder.toString();
            }

        },

        /**
         * <code>IRIDE</code> <code>Digital Identity</code> <code>toString</code> representation.
         */
        TO_STRING_REPRESENTATION {

            /**
             * Format the given {@link IrideIdentity} instance returning an <code>IRIDE</code> <code>Digital Identity</code> internal representation,
             * with the following format: {@link IrideIdentity#getCodFiscale()} + {@link IrideIdentityToken#SEPARATOR}
             *                            {@link IrideIdentity#getNome()} + {@link IrideIdentityToken#SEPARATOR}
             *                            {@link IrideIdentity#getCognome()} + {@link IrideIdentityToken#SEPARATOR}
             *                            {@link IrideIdentity#getIdProvider()} + {@link IrideIdentityToken#SEPARATOR}
             *                            {@link IrideIdentity#getTimestamp()} + {@link IrideIdentityToken#SEPARATOR}
             *                            {@link IrideIdentity#getLivelloAutenticazione()} + {@link IrideIdentityToken#SEPARATOR}
             *                            {@link IrideIdentity#getMac()}.
             */
            /*
             * (non-Javadoc)
             * @see org.geoserver.security.iride.entity.IrideIdentityFormatter.FormatStyle#format(org.geoserver.security.iride.entity.IrideIdentity)
             */
            @Override
            String format(IrideIdentity irideIdentity) {
                final StringBuilder builder = new StringBuilder();
                builder.append(irideIdentity.getCodFiscale()).append(IrideIdentityToken.SEPARATOR)
                       .append(irideIdentity.getNome()).append(IrideIdentityToken.SEPARATOR)
                       .append(irideIdentity.getCognome()).append(IrideIdentityToken.SEPARATOR)
                       .append(irideIdentity.getIdProvider()).append(IrideIdentityToken.SEPARATOR)
                       .append(irideIdentity.getTimestamp()).append(IrideIdentityToken.SEPARATOR)
                       .append(irideIdentity.getLivelloAutenticazione()).append(IrideIdentityToken.SEPARATOR)
                       .append(irideIdentity.getMac());

                return builder.toString();
            }

        },

        /**
         * <code>IRIDE</code> <code>Digital Identity</code> reflection <code>toString</code> representation.
         *
         * @see ToStringReflectionBuilder#reflectToString(Object)
         */
        REFLECTION_TO_STRING {

            /**
             * Format the given {@link IrideIdentity} instance returning an <code>IRIDE</code> <code>Digital Identity</code> internal representation,
             * using {@link ToStringReflectionBuilder#reflectToString(IrideIdentity)}.
             */
            /*
             * (non-Javadoc)
             * @see org.geoserver.security.iride.entity.IrideIdentityFormatter.FormatStyle#format(org.geoserver.security.iride.entity.IrideIdentity)
             */
            @Override
            String format(IrideIdentity irideIdentity) {
                return ToStringReflectionBuilder.reflectToString(irideIdentity);
            }

        },
        ;

        /**
         * Returns the formatted representation of the given <code>IRIDE</code> <code>Digital Identity</code> entity.
         *
         * @param irideIdentity the <code>IRIDE</code> <code>Digital Identity</code> entity to format
         * @return the formatted representation of the given <code>IRIDE</code> <code>Digital Identity</code> entity
         */
        abstract String format(IrideIdentity irideIdentity);
    }


    /**
     * Returns the formatted representation of the given <code>IRIDE</code> <code>Digital Identity</code> entity
     * as per given {@link FormatStyle}, or {@code null} if no {@link FormatStyle} is given.
     *
     * @param irideIdentity <code>IRIDE</code> <code>Digital Identity</code> entity object to format
     * @param style the given {@link FormatStyle}
     * @return the formatted representation of the given <code>IRIDE</code> <code>Digital Identity</code> entity
     *         as per given {@link FormatStyle}, or {@code null} if no {@link FormatStyle} is given
     */
    public String format(IrideIdentity irideIdentity, FormatStyle style) {
        if (irideIdentity == null || style == null) {
            return null;
        }

        return style.format(irideIdentity);
    }

}
