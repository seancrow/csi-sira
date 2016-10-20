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

import org.apache.commons.validator.routines.UrlValidator;
import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.iride.util.builder.Builder;
import org.geoserver.security.iride.util.factory.util.UrlValidatorFactory;

/**
 * Candidate <code>IRIDE</code> server <code>URL</code> builder utility:
 * the <code>URL</code> is first parsed ({@link #parse(String)}) and then validated ({@link #validate(String)}).
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public final class IrideUrlBuilder implements Builder<String> {

    /**
     * Candidate <code>IRIDE</code> server <code>URL</code>.
     */
    private final String url;

    /**
     * Constructor.
     *
     * @param url candidate <code>IRIDE</code> server <code>URL</code>
     */
    public IrideUrlBuilder(String url) {
        this.url = url;
    }

    /**
     * "Builds" the candidate <code>IRIDE</code> server <code>URL</code>, returning the result.
     * May throw an {@link IllegalArgumentException} if the given url is not deemed <em>valid</em>.
     *
     * @param url candidate <code>IRIDE</code> server <code>URL</code>
     * @return the "built" <code>IRIDE</code> server <code>URL</code>
     * @see UrlValidator#isValid(String)
     */
    public static String buildServerUrl(String url) {
        return new IrideUrlBuilder(url).build();
    }

    /**
     * Parse the given <code>IRIDE</code> server <code>URL</code>,
     * looking for a property name placeholder (<code>${...}</code>).<p>
     * If found, the property value will be retrieved from looking for the property name
     * in the internallly cached <code>Spring</code> application context.
     *
     * @param url <code>IRIDE</code> server <code>URL</code>
     * @return parsed <code>IRIDE</code> server <code>URL</code>
     */
    private static String parse(String url) {
        if (url != null && url.startsWith("${") && url.endsWith("}")) {
            return GeoServerExtensions.getProperty(url.substring(2, url.length() - 1));
        }

        return url;
    }

    /**
     * Returns the given <code>IRIDE</code> server <code>URL</code> if it's deemed a valid <code>URL</code>,
     * throwing an {@link IllegalArgumentException} otherwise.
     *
     * @param url <code>IRIDE</code> server <code>URL</code>
     * @return the given <code>IRIDE</code> server <code>URL</code> if it's deemed a valid <code>URL</code>
     * @throws IllegalArgumentException if the given <code>IRIDE</code> server <code>URL</code> is not deemed a valid <code>URL</code>
     * @see UrlValidator#isValid(String)
     */
    private static String validate(String url) {
        if (! UrlValidatorFactory.createUrlValidator().isValid(url)) {
            throw new IllegalArgumentException(String.format(
                "'%s' is not a valid IRIDE server URL ", url
            ));
        }

        return url;
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.iride.util.builder.Builder#build()
     */
    /**
     * "Builds" the candidate <code>IRIDE</code> server <code>URL</code>, returning the result.
     *
     * @return the "built" <code>IRIDE</code> server <code>URL</code>
     */
    @Override
    public String build() {
        return validate(parse(this.url));
    }

}
