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
package org.geoserver.security.iride.entity.converter;

import java.util.logging.Logger;

import org.geotools.util.logging.Logging;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.support.DependencyInjectionTestExecutionListener;

import com.thoughtworks.xstream.XStream;

/**
 * <a href="http://x-stream.github.io/"><code>XStream</code></a> configured for <code>IRIDE</code> entities <code>JUnit</code> Test Case.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {
    "classpath:/testContext.xml",
    "classpath:/testEntitiesContext.xml",
    "classpath:/templateContext.xml"
})
@TestExecutionListeners({ DependencyInjectionTestExecutionListener.class })
public abstract class AbstractXStreamTest {

    /**
     * Logger.
     */
    protected final Logger logger = Logging.getLogger(this.getClass());

    /**
     * The <a href="http://x-stream.github.io/"><code>XStream</code></a> instance, configured for <code>IRIDE</code> entities.
     */
    @Autowired
    private XStream xs;

    /**
     * Get the <a href="http://x-stream.github.io/"><code>XStream</code></a> instance, configured for <code>IRIDE</code> entities.
     *
     * @return the <a href="http://x-stream.github.io/"><code>XStream</code></a> instance, configured for <code>IRIDE</code> entities
     */
    protected final XStream getXs() {
        return this.xs;
    }

}
