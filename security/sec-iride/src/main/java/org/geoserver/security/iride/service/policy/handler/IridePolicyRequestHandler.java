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
package org.geoserver.security.iride.service.policy.handler;

import java.io.IOException;
import java.util.Map;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.HttpStatus;
import org.geoserver.security.iride.service.policy.IridePolicy;
import org.geoserver.security.iride.util.builder.http.HttpPostBuilder;
import org.geoserver.security.iride.util.template.TemplateEngine;

/**
 * <code>IRIDE</code> service "policy" <em>request</em> handler.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public final class IridePolicyRequestHandler extends AbstractIridePolicyHandler {

    /**
     * {@link HttpClient} instance.
     */
    private HttpClient httpClient;

    /**
     * <code>HTTP</code> headers to use when requesting the {@link #policy}.
     */
    private Header[] httpHeaders;

    /**
     * {@link TemplateEngine} implementation.
     */
    private TemplateEngine templateEngine;

    /**
     * <code>HTTP</code> <code>POST</code> <em>request</em> builder.
     */
    private HttpPostBuilder httpPostBuilder;

    /**
     * Constructor.
     *
     * @param policy <code>IRIDE</code> service "policy": the specific service operation to <em>request</em>
     */
    public IridePolicyRequestHandler(IridePolicy policy) {
        super(policy);
    }

    /**
     * Set the {@link HttpClient} instance.
     *
     * @param httpClient the {@link HttpClient} instance
     */
    public void setHttpClient(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    /**
     * Get the {@link HttpClient} instance.
     *
     * @return the {@link HttpClient} instance
     */
    public HttpClient getHttpClient() {
        return this.httpClient;
    }

    /**
     * Get the <code>HTTP</code> headers to use when requesting the {@link #policy}.
     *
     * @return the <code>HTTP</code> headers to use when requesting the {@link #policy}
     */
    public Header[] getHttpHeaders() {
        return this.httpHeaders;
    }

    /**
     * Set the <code>HTTP</code> headers to use when requesting the {@link #policy}.
     *
     * @param httpHeaders the <code>HTTP</code> headers to use when requesting the {@link #policy}
     */
    public void setHttpHeaders(Header[] httpHeaders) {
        this.httpHeaders = httpHeaders;
    }

    /**
     * Set the {@link TemplateEngine} implementation.
     *
     * @param templateEngine the {@link TemplateEngine} implementation
     */
    public void setTemplateEngine(TemplateEngine templateEngine) {
        this.templateEngine = templateEngine;
    }

    /**
     * Get the {@link TemplateEngine} implementation.
     *
     * @return the {@link TemplateEngine} implementation
     */
    public TemplateEngine getTemplateEngine() {
        return this.templateEngine;
    }

    /**
     * Get the <code>HTTP</code> <code>POST</code> <em>request</em> builder.
     *
     * @return the <code>HTTP</code> <code>POST</code> <em>request</em> builder
     */
    public HttpPostBuilder getHttpPostBuilder() {
        return this.httpPostBuilder;
    }

    /**
     * Set the <code>HTTP</code> <code>POST</code> <em>request</em> builder.
     *
     * @param httpPostBuilder the <code>HTTP</code> <code>POST</code> <em>request</em> builder
     */
    public void setHttpPostBuilder(HttpPostBuilder httpPostBuilder) {
        this.httpPostBuilder = httpPostBuilder;
    }

    /**
     *
     * @param serverURL
     * @param params
     * @return
     * @throws IOException
     */
    public String handlePolicy(String serverURL, Map<String, Object> params) throws IOException {
        final String     requestXml        = this.createPolicyRequestXml(params);
        final HttpMethod requestHttpMethod = this.createPolicyRequestMethod(requestXml, serverURL);

        try {
            final int status = this.getHttpClient().executeMethod(requestHttpMethod);
            if (status == HttpStatus.SC_OK ) {
                final String responseXml = requestHttpMethod.getResponseBodyAsString();

                LOGGER.info("Response received from IRIDE: " + responseXml);

                return responseXml;
            } else {
                LOGGER.info("Got error from IRIDE: " + String.format("%d %s", status, HttpStatus.getStatusText(status)));

                return "";
            }
        } finally {
            requestHttpMethod.releaseConnection();
        }
    }

    /**
     *
     * @param params
     * @return
     * @throws IOException
     */
    private String createPolicyRequestXml(Map<String, Object> params) throws IOException {
        return this.getTemplateEngine().process(this.getPolicy().getServiceName(), params);
    }

    /**
     *
     * @param requestXml
     * @param serverURL
     * @return
     * @throws IOException
     */
    private HttpMethod createPolicyRequestMethod(String requestXml, String serverURL) {
        return this.getHttpPostBuilder().build(serverURL, requestXml, this.getHttpHeaders());
    }

}
