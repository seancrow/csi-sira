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
package org.geoserver.security.iride.util.builder.http;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.RequestEntity;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.geoserver.security.iride.util.builder.Builder;
import org.geoserver.security.iride.util.logging.LoggerProvider;

import com.google.common.net.MediaType;

/**
 * <code>HTTP</code> <code>POST</code> request builder.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public class HttpPostBuilder implements Builder<PostMethod> {

    /**
     * Logger.
     */
    private static final Logger LOGGER = LoggerProvider.UTIL.getLogger();

    /**
     * No <code>HTTP</code> headers set.
     */
    private static final Header[] NO_HEADERS = new Header[0];

    /**
     * An absolute or relative <code>URI</code>
     */
    private String uri;

    /**
     * The content to set the <code>POST</code> request with.
     */
    private String content;

    /**
     * <code>HTTP</code> headers to use when building the <code>POST</code> request.
     */
    private Header[] headers;

    /**
     * Get the the absolute or relative <code>URI</code>.
     *
     * @return the absolute or relative <code>URI</code>
     */
    public String getUri() {
        return this.uri;
    }

    /**
     * Set the absolute or relative <code>URI</code>.
     *
     * @param uri the absolute or relative <code>URI</code>
     */
    public void setUri(String uri) {
        this.uri = uri;
    }

    /**
     * Get the content to set the <code>POST</code> request with.
     *
     * @return the content to set the <code>POST</code> request with
     */
    public String getContent() {
        return this.content;
    }

    /**
     * Set the content to set the <code>POST</code> request with.
     *
     * @param content the content to set the <code>POST</code> request with
     */
    public void setContent(String content) {
        this.content = content;
    }

    /**
     * Get the <code>HTTP</code> headers to use when building the <code>POST</code> request.
     *
     * @return the <code>HTTP</code> headers to use when building the <code>POST</code> request
     */
    public Header[] getHeaders() {
        return this.headers;
    }

    /**
     * Set the <code>HTTP</code> headers to use when building the <code>POST</code> request.
     *
     * @param headers the <code>HTTP</code> headers to use when building the <code>POST</code> request
     */
    public void setHeaders(Header[] headers) {
        this.headers = headers == null ? NO_HEADERS : headers;
    }

    /**
     * Utility method to "prepare" the <code>HTTP</code> <code>POST</code> request builder, returning it.
     *
     * @param uri the absolute or relative <code>URI</code>
     * @param content the content to set the <code>POST</code> request with
     * @param headers the <code>HTTP</code> headers to use when building the <code>POST</code> request
     * @return the "prepare" <code>HTTP</code> <code>POST</code> request builder
     */
    public PostMethod build(String uri, String content, Header[] headers) {
        this.setUri(uri);
        this.setContent(content);
        this.setHeaders(headers);

        return this.build();
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.iride.util.builder.Builder#build()
     */
    @Override
    public PostMethod build() {
        try {
            return this.createPostMethod();
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "HTTP POST method build failed: " + e.getMessage(), e);

            return null;
        }
    }

    /**
     *
     * @param requestXml
     * @param serverURL
     * @return
     * @throws IOException
     */
    private PostMethod createPostMethod() throws IOException {
        final PostMethod post = new PostMethod(this.getUri());
        post.setRequestEntity(this.createRequestEntity());
        for (final Header header : this.getHeaders()) {
            post.setRequestHeader(header);
        }

        return post;
    }

    /**
     *
     * @param requestXml
     * @return
     * @throws IOException
     */
    private RequestEntity createRequestEntity() throws IOException {
        return new StringRequestEntity(
            this.getContent(),
            MediaType.APPLICATION_XML_UTF_8.toString(),
            StandardCharsets.UTF_8.name()
        );
    }

}
