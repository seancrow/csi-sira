package org.geoserver.security.iride.util.builder;

import org.apache.commons.validator.routines.UrlValidator;
import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.iride.util.factory.UrlValidatorFactory;

/**
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public final class IrideServerURLBuilder implements Builder<String> {

    /**
     * Candidate <code>IRIDE</code> server <code>URL</code>.
     */
    private final String url;

    /**
     * "Builds" the candidate <code>IRIDE</code> server <code>URL</code>, returning the result.
     * May throw an {@link IllegalArgumentException} if the given url is not deemed <em>valid</em>.
     *
     * @param url candidate <code>IRIDE</code> server <code>URL</code>
     * @see UrlValidator#isValid(String)
     */
    public static String buildServerURL(String url) {
        return new IrideServerURLBuilder(url).build();
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
            url = GeoServerExtensions.getProperty(url.substring(2, url.length() - 1));
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
        if (! UrlValidatorFactory.getDefaultUrlValidator().isValid(url)) {
            throw new IllegalArgumentException(String.format(
                "'%s' is not a valid IRIDE server URL ", url
            ));
        }

        return url;
    }

    /**
     * Constructor.
     *
     * @param url candidate <code>IRIDE</code> server <code>URL</code>
     */
    public IrideServerURLBuilder(String url) {
        this.url = url;
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.iride.util.builder.Builder#build()
     */
    /**
     * "Builds" the candidate <code>IRIDE</code> server <code>URL</code>, returning the result.
     */
    public String build() {
        return validate(parse(this.url));
    }

}
