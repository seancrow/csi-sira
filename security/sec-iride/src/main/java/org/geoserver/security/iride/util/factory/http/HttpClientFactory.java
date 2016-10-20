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
package org.geoserver.security.iride.util.factory.http;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpConnectionManager;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.params.HttpConnectionManagerParams;
import org.geoserver.security.iride.util.factory.AbstractFactory;

/**
 * <a href="http://hc.apache.org/httpclient-legacy/index.html"><code>HttpClient</code></a> <em>default</em> Factory.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public class HttpClientFactory extends AbstractFactory<HttpClient> {

    /**
     * Default <code>timeout</code> value in milliseconds.
     */
    public static final int DEFAULT_TIMEOUT = 30000;

    /**
     * The timeout (in milliseconds) for waiting until a connection is established.
     * A value of zero means that no timeout is used.
     */
    private Integer connectionTimeout;

    /**
     * The socket timeout (<code>SO_TIMEOUT</code>)(in milliseconds) for waiting data.
     * A value of zero means that no timeout is used.
     */
    private Integer socketTimeout;

    /**
     * Static factory method, useful for testing.
     *
     * @return a new {@link HttpClient} object
     */
    public static HttpClient createHttpClient() {
        final HttpClientFactory factory = new HttpClientFactory();

        return factory.create();
    }

    /**
     * Set the timeout (in milliseconds) for waiting until a connection is established.
     * A value of zero means that no timeout is used.
     *
     * @param connectionTimeout the timeout(in milliseconds) for waiting until a connection is established
     */
    public final void setConnectionTimeout(Integer connectionTimeout) {
        this.connectionTimeout = connectionTimeout;
    }

    /**
     * Set the socket timeout (<code>SO_TIMEOUT</code>)(in milliseconds) for waiting data.
     * A value of zero means that no timeout is used.
     *
     * @param socketTimeout the default socket timeout (<code>SO_TIMEOUT</code>)(in milliseconds) for waiting data
     */
    public final void setSocketTimeout(Integer socketTimeout) {
        this.socketTimeout = socketTimeout;
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.iride.util.factory.http.HttpClientFactory#newHttpClient()
     */
    /**
     * Return a new {@link HttpClient} object, using a {@link MultiThreadedHttpConnectionManager} configured as follows:
     * <ul>
     *   <li>The timeout (in milliseconds) for waiting until a connection is established set to {@link #connectionTimeout},
     *   or {@value #DEFAULT_TIMEOUT} if {@link #connectionTimeout} is not set (i.e.: is {@code null})<br />
     *   A value of zero means that no timeout is used</li>
     *   <li>The socket timeout (<code>SO_TIMEOUT</code>)(in milliseconds) for waiting data set to {@link #socketTimeout},
     *   or {@value #DEFAULT_TIMEOUT} if {#link {@link #socketTimeout} is not set (i.e.: is {@code null})<br />
     *   A value of zero means that no timeout is used</li>
     * </ul>
     */
    @Override
    protected final HttpClient newInstance() {
        final HttpConnectionManagerParams params = new HttpConnectionManagerParams();
        params.setConnectionTimeout(this.connectionTimeout == null ? DEFAULT_TIMEOUT : this.connectionTimeout);
        params.setSoTimeout(this.socketTimeout == null ? DEFAULT_TIMEOUT : this.socketTimeout);

        final HttpConnectionManager manager = new MultiThreadedHttpConnectionManager();
        manager.setParams(params);

        final HttpClient httpClient = new HttpClient();
        httpClient.setHttpConnectionManager(manager);

        return httpClient;
    }

}
