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
package test.org.geoserver.security.iride.util.factory.http;

import java.io.IOException;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.HttpStatus;
import org.geoserver.security.iride.util.factory.AbstractFactory;

/**
 * <a href="http://hc.apache.org/httpclient-legacy/index.html"><code>HttpClient</code></a> <em>test stub</em> Factory.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public class HttpClientFactory extends AbstractFactory<HttpClient> {

    /* (non-Javadoc)
     * @see org.geoserver.security.iride.util.factory.http.HttpClientFactory#newHttpClient()
     */
    /**
     * Return a new {@link HttpClient} object useful for testing.
     * <p>Each method execution always returns {@link HttpStatus#SC_OK} status code.
     */
    @Override
    protected final HttpClient newInstance() {
        return new HttpClient() {

            /*
             * (non-Javadoc)
             * @see org.apache.commons.httpclient.HttpClient#executeMethod(org.apache.commons.httpclient.HttpMethod)
             */
            @Override
            public int executeMethod(HttpMethod method) throws IOException, HttpException {
                return HttpStatus.SC_OK;
            }

        };
    }

}
