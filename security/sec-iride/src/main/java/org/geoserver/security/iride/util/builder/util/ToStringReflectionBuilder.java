/*
 *  GeoServer Security Provider plugin used for doing authentication and authorization operations using CSI-Piemonte IRIDE Service.
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
package org.geoserver.security.iride.util.builder.util;

import static org.apache.commons.lang.builder.ToStringBuilder.reflectionToString;

import org.apache.commons.lang.builder.StandardToStringStyle;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;

/**
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public final class ToStringReflectionBuilder {

    /**
     * A singleton {@link ToStringStyle} instance, configured as follows:
     * <ul>
     *     <li><code>arrayStart</code>: <code>"["</code></li>
     *     <li><code>arrayEnd</code>: <code>"]"</code></li>
     *     <li><code>contentStart</code>: <code>"("</code></li>
     *     <li><code>fieldSeparator</code>: <code>", "</code></li>
     *     <li><code>fieldSeparatorAtStart</code>: <code>true</code></li>
     *     <li><code>contentEnd</code>: <code>")"</code></li>
     *     <li><code>useShortClassName</code>: <code>true</code></li>
     *     <li><code>nullText</code>: <code>"&lt;NULL&gt;"</code></li>
     * </ul>
     */
    public static final ToStringStyle TO_STRING_STYLE = new StandardToStringStyle() {

        private static final long serialVersionUID = -7977293159579371869L;

    {
        this.setArrayStart("[");
        this.setArrayEnd("]");
        this.setContentStart("(");
        this.setFieldSeparator(", ");
        this.setContentEnd(")");
        this.setUseShortClassName(true);
        this.setNullText(NULL_TEXT);
    }};

    /**
     * {@code null} textual representation.
     */
    public static final String NULL_TEXT = "<null>";

    /**
     * Constructor.
     */
    private ToStringReflectionBuilder() {
        /* NO-OP */
    }

    /**
     * Restituisce una rappresentazione testuale,
     * ottenuta tramite <code>Reflection API</code>, dell'oggetto fornito.
     *
     * @see ToStringBuilder#reflectionToString(Object, ToStringStyle)
     * @param object l'oggetto di cui fornire una rappresentazione testuale,
     *        ottenuta tramite <code>Reflection API</code>
     * @return una rappresentazione testuale,
     *         ottenuta tramite <code>Reflection API</code>, dell'oggetto fornito.
     */
    public static <T> String reflectToString(T object) {
        return reflectionToString((T) object, TO_STRING_STYLE);
    }

}
