/*
 *  REST service to query for IRIDE roles using CSI-Piemonte IRIDE Service.
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
package it.csi.sira.frontend.iride.controller;

import java.io.IOException;

import org.geoserver.security.iride.entity.IrideApplication;
import org.geoserver.security.iride.entity.IrideIdentity;
import org.geoserver.security.iride.entity.IrideRole;
import org.geoserver.security.iride.service.IrideService;
import org.geoserver.security.iride.util.logging.LoggerProvider;
import org.slf4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * <code>IRIDE</code> <code>REST</code> action, backed by <a href="http://www.csipiemonte.it/">CSI</a> <code>IRIDE</code> service.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
@Controller
@RequestMapping(method = RequestMethod.GET, value = Constants.MAPPING_IRIDE_SERVICE)
public class IrideServiceController {

    /**
     * Logger.
     */
    private static final Logger LOGGER = LoggerProvider.getLogger(IrideServiceController.class);

    /**
     * "No roles" empty {@link IrideRole} array.
     */
    private static final IrideRole[] NO_ROLES = new IrideRole[0];

    /**
     * <code>IRIDE</code> service "policies" enforcer instance.
     */
    private IrideService irideService;

    /**
     * @return the irideService
     */
    public IrideService getIrideService() {
        return this.irideService;
    }

    /**
     * @param irideService the irideService to set
     */
    public void setIrideService(IrideService irideService) {
        this.irideService = irideService;
    }

    /**
     *
     * @param user
     * @return
     */
    @RequestMapping(
    	headers = {
    		Constants.HEADER_ACCEPT_JSON,
    		Constants.HEADER_SHIBBOLETH_IRIDE,
    	},
    	value = Constants.MAPPING_ROLES_FOR_DIGITAL_IDENTITY
    )
    @ResponseBody
    public ResponseEntity<String> getRolesForDigitalIdentity(
    	@RequestHeader(
    		value = Constants.HEADER_SHIBBOLETH_IRIDE,
    		defaultValue = ""
    	) String user) {
        LOGGER.trace("IRIDE Digital Identity: {}", user);

        try {
            final IrideRole[] roles = this.getRolesForUser(user);

            LOGGER.trace("Got {} roles for IRIDE Digital Identity {}", roles.length, user);

            return new ResponseEntity<>(this.toJson(roles), HttpStatus.OK);
        } catch (IOException e) {
            LOGGER.error("IRIDE roles retrieval for Digital Identity {} error: {}", user, e.getMessage(), e);

            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     *
     * @param user
     * @return
     */
    private IrideRole[] getRolesForUser(String user) {
        IrideRole[] roles = NO_ROLES;

        final IrideIdentity irideIdentity = IrideIdentity.parseIrideIdentity(user);
        if (irideIdentity != null) {
            roles = this.getIrideService().findRuoliForPersonaInApplication(
                irideIdentity,
                new IrideApplication(Constants.APPLICATION_NAME)
            );
        }

        return roles;
    }

    /**
     *
     * @param roles
     * @return
     * @throws JsonProcessingException
     */
    private String toJson(IrideRole[] roles) throws JsonProcessingException {
        final ObjectMapper mapper = new ObjectMapper();

        final String json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(roles);

        LOGGER.trace("IRIDE roles to JSON: {}", json);

        return json;
    }

}
