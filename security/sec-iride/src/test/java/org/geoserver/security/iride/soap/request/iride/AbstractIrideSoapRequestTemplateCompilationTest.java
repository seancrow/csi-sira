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
package org.geoserver.security.iride.soap.request.iride;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.HashMap;
import java.util.Map;

import org.geoserver.security.iride.AbstractXmlUnitTest;
import org.geoserver.security.iride.util.Utils;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;

/**
 * Base class for <code>IRIDE</code> service <code>SOAP</code> request template compilation (using <a href="http://freemarker.org/"><code>FreeMarker</code></a>) <code>JUnit</code> Test.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {
    "classpath:/testContext.xml",
    "classpath:/testEntitiesContext.xml",
	"classpath:/templateContext.xml"
})
public abstract class AbstractIrideSoapRequestTemplateCompilationTest extends AbstractXmlUnitTest {

    /**
     * <code>FreeMarker</code>'ed <code>SOAP</code> request template file extension.
     */
    private static String templateExtension;

    /**
     * <a href="http://freemarker.org/"><code>FreeMarker</code></a> Template {@link Configuration}.
     */
    private Configuration templateConfiguration;

    /**
     * <code>FreeMarker</code> template <code>data model</code>.
     */
    private Map<String, Object> dataModel;

    /**
     * <code>FreeMarker</code>'ed <code>SOAP</code> request template file name, without extension.
     */
    private String templateName;

    /**
     * Set the <code>FreeMarker</code>'ed <code>SOAP</code> request template file extension.
     *
     * @param tplExtension the <code>FreeMarker</code>'ed <code>SOAP</code> request template file extension
     */
    public static final void setTemplateExtension(String tplExtension) {
        templateExtension = tplExtension;
    }

    /**
     * Set the <a href="http://freemarker.org/"><code>FreeMarker</code></a> Template {@link Configuration}.
     *
     * @param templateConfiguration the <a href="http://freemarker.org/"><code>FreeMarker</code></a> Template {@link Configuration}
     */
    @Value("#{templateConfiguration}")
    protected final void setTemplateConfiguration(Configuration templateConfiguration) {
        this.templateConfiguration = templateConfiguration;
    }

    /**
     * Returns the <code>FreeMarker</code> template <code>data model</code>.
     *
     * @return the <code>FreeMarker</code> template <code>data model</code>
     */
    protected final Map<String, Object> getDataModel() {
        return this.dataModel;
    }

    /**
     * Set the <code>FreeMarker</code> template <code>data model</code>.
     *
     * @param the <code>FreeMarker</code> template <code>data model</code>
     */
    protected void setDataModel(Map<String, Object> dataModel) {
        this.dataModel = dataModel == null ? new HashMap<String, Object>() : dataModel;
    }

    /**
     *
     * @return
     */
    protected final String getTemplateName() {
        return this.templateName;
    }

    /**
     *
     * @param templateName
     */
    protected void setTemplateName(String templateName) {
        this.templateName = templateName;
    }

    /**
     *
     * @return
     * @throws IOException
     */
    protected final Template getTemplate() throws IOException {
        return this.templateConfiguration.getTemplate(
            Utils.ensureFileWithExtension(this.getTemplateName(), templateExtension),
            this.templateConfiguration.getDefaultEncoding()
        );
    }

    /**
     *
     * @return
     * @throws TemplateException
     * @throws IOException
     */
    protected final String processTemplate() throws TemplateException, IOException {
        final Template            template  = this.getTemplate();
        final Map<String, Object> dataModel = this.getDataModel();

        final Writer out = new StringWriter();

        logger.fine("IRIDE SOAP request '" + this.getTemplateName() + "' template: \n" + template);
        logger.fine("IRIDE SOAP request '" + this.getTemplateName() + "' dataModel: \n" + dataModel);

        template.process(dataModel, out);

        final String output = out.toString();

        logger.fine("IRIDE SOAP request '" + this.getTemplateName() + "' template processing output: \n" + output);

        return output;
    }

}
