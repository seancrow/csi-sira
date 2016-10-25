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

import java.util.Set;

import javax.xml.transform.Source;
import javax.xml.transform.TransformerException;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.geoserver.security.iride.service.policy.IridePolicy;
import org.geoserver.security.iride.util.xml.transform.XmlTransformer;

import com.google.common.collect.Sets;
import com.thoughtworks.xstream.XStream;

/**
 * <code>IRIDE</code> service "policy" <em>response</em> handler.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public final class IridePolicyResponseHandler extends AbstractIridePolicyHandler {

    /**
     * <a href="https://en.wikipedia.org/wiki/XSLT"><code>XML</code> transformer</a>.
     */
    private XmlTransformer xmlTransformer;

    /**
     * The <a href="https://en.wikipedia.org/wiki/XSLT"><code>XML</code> transformations</a>
     * with which to process a <code>IRIDE</code> service "policy" <em>response</em>.
     */
    private Set<Source> transformations;

    /**
     * <a href="http://x-stream.github.io/"><code>XStream</code></a> instance, configured for <code>IRIDE</code> entities.
     */
    private XStream xs;

    /**
     * Constructor.
     *
     * @param policy <code>IRIDE</code> service "policy": the specific service operation to handle
     */
    public IridePolicyResponseHandler(IridePolicy policy) {
        super(policy);
    }

    /**
     * Get the <a href="https://en.wikipedia.org/wiki/XSLT"><code>XML</code> transformer</a>.
     *
     * @return the <a href="https://en.wikipedia.org/wiki/XSLT"><code>XML</code> transformer</a>
     */
    public XmlTransformer getXmlTransformer() {
        return this.xmlTransformer;
    }

    /**
     * Set the <a href="https://en.wikipedia.org/wiki/XSLT"><code>XML</code> transformer</a>.
     *
     * @param xmlTransformer the <a href="https://en.wikipedia.org/wiki/XSLT"><code>XML</code> transformer</a>
     */
    public void setXmlTransformer(XmlTransformer xmlTransformer) {
        this.xmlTransformer = xmlTransformer;
    }

    /**
     * Set the <a href="https://en.wikipedia.org/wiki/XSLT"><code>XML</code> transformations</a>
     * with which to process a <code>IRIDE</code> service "policy" <em>response</em>.
     *
     * @return the <a href="https://en.wikipedia.org/wiki/XSLT"><code>XML</code> transformations</a>
     *         with which to process a <code>IRIDE</code> service "policy" <em>response</em>
     */
    public Set<Source> getTransformations() {
        return this.transformations;
    }

    /**
     * Get the <a href="https://en.wikipedia.org/wiki/XSLT"><code>XML</code> transformations</a>
     * with which to process a <code>IRIDE</code> service "policy" <em>response</em>.
     *
     * @param transformations the <a href="https://en.wikipedia.org/wiki/XSLT"><code>XML</code> transformations</a>
     *        with which to process a <code>IRIDE</code> service "policy" <em>response</em>
     */
    public void setTransformations(Set<Source> transformations) {
        if (transformations == null) {
            this.transformations = Sets.<Source>newLinkedHashSet();
        }

        this.transformations = transformations;
    }

    /**
     * Get the <a href="http://x-stream.github.io/"><code>XStream</code></a> instance, configured for <code>IRIDE</code> entities.
     *
     * @return the <a href="http://x-stream.github.io/"><code>XStream</code></a> instance, configured for <code>IRIDE</code> entities
     */
    public XStream getXs() {
        return this.xs;
    }

    /**
     * Set the <a href="http://x-stream.github.io/"><code>XStream</code></a> instance, configured for <code>IRIDE</code> entities.
     *
     * @param xs the <a href="http://x-stream.github.io/"><code>XStream</code></a> instance, configured for <code>IRIDE</code> entities
     */
    public void setXs(XStream xs) {
        if (xs == null) {
            // an XStream just to avoid NPEs with no IRIDE-specific configuration
            xs = new XStream();
        }

        this.xs = xs;
    }

    /**
     *
     * @param policyResponse
     * @return
     * @throws TransformerException
     */
    public Object handlePolicy(String policyResponse) throws TransformerException {
        final String policyResponseMarshalledXml = this.createPolicyResponseMarshalledXml(policyResponse);

        return this.getXs().fromXML(policyResponseMarshalledXml);
    }

    /**
     *
     * @param policyResponse
     * @return
     * @throws TransformerException
     */
    private String createPolicyResponseMarshalledXml(String policyResponse) throws TransformerException {
        String policyResponseMarshalledXml = null;

        for (final Source transformation : this.getTransformations()) {
            final StreamSource source = XmlTransformer.newStreamSource(
                policyResponseMarshalledXml == null
                    ? policyResponse
                    : policyResponseMarshalledXml
            );
            final StreamResult output = XmlTransformer.newStreamResult();

            this.getXmlTransformer().transform(transformation, source, output);

            policyResponseMarshalledXml = output.toString();
        }

        return policyResponseMarshalledXml;
    }

}
