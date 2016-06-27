package org.geoserver.security.iride.util.factory;

import org.apache.commons.validator.routines.UrlValidator;

/**
 * {@link UrlValidator} factory
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public final class UrlValidatorFactory {

    /**
     * Default {@link UrlValidator}, configured as follows to:
     * <ul>
     *   <li>allow only the following <code>HTTP</code> schemas:</li>
     *   <ul>
     *     <li>http</li>
     *     <li>https</li>
     *   </ul>
     *   <li>not allow <code>HTTP</code> fragments</li>
     * </ul>
     *
     */
    private static final UrlValidator DEFAULT_URL_VALIDATOR = new UrlValidator(
        new String[] {"http", "https"},
        UrlValidator.NO_FRAGMENTS
    );

    /**
     * Returns the default {@link UrlValidator}.
     *
     * @return the default {@link UrlValidator}
     */
    public static UrlValidator getDefaultUrlValidator() {
        return DEFAULT_URL_VALIDATOR;
    }

    /**
     * Constructor.
     */
    private UrlValidatorFactory() {
        /* NOP */
    }

}
