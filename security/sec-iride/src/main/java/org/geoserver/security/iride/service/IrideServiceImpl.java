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
package org.geoserver.security.iride.service;

import static org.geoserver.security.iride.util.builder.util.IrideUrlBuilder.buildServerUrl;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.transform.TransformerException;

import org.apache.commons.lang.StringUtils;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.iride.config.IrideSecurityServiceConfig;
import org.geoserver.security.iride.entity.IrideApplication;
import org.geoserver.security.iride.entity.IrideIdentity;
import org.geoserver.security.iride.entity.IrideRole;
import org.geoserver.security.iride.entity.IrideUseCase;
import org.geoserver.security.iride.service.policy.IridePolicy;
import org.geoserver.security.iride.service.policy.IridePolicyManager;
import org.geoserver.security.iride.util.logging.LoggerProvider;

/**
 * <code>IRIDE</code> service implementation.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public final class IrideServiceImpl implements IrideService {

    /**
     * Logger.
     */
    private static final Logger LOGGER = LoggerProvider.POLICY.getLogger();

    /**
     * Policy execution error message format.
     */
    private static final String ERROR_MESSAGE_FORMAT = "%s error: %s";

    /**
     * <code>IRIDE</code> server <code>URL</code>.
     */
    private String serverURL;

    /**
     * <code>IRIDE</code> service "policies" manager.
     */
    private IridePolicyManager policyManager;

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.iride.service.IrideService#initializeFromConfig(org.geoserver.security.config.SecurityNamedServiceConfig)
     */
    @Override
    public void initializeFromConfig(SecurityNamedServiceConfig config) throws IOException {
        if (! (config instanceof IrideSecurityServiceConfig)) {
            throw new IllegalArgumentException("Config object must be of IrideSecurityServiceConfig type");
        }

        final IrideSecurityServiceConfig irideConfig = (IrideSecurityServiceConfig) config;

        this.serverURL = buildServerUrl(irideConfig.getServerURL());
    }

    /**
     * Get the <code>IRIDE</code> service "policies" manager.
     *
     * @return the <code>IRIDE</code> service "policies" manager
     */
    public IridePolicyManager getPolicyManager() {
        return this.policyManager;
    }

    /**
     * Set the <code>IRIDE</code> service "policies" manager.
     *
     * @param policyManager the <code>IRIDE</code> service "policies" manager
     */
    public void setPolicyManager(IridePolicyManager policyManager) {
        this.policyManager = policyManager;
    }

    // === PolicyEnforcerBase interface === BEGIN =============================

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.iride.policy.PolicyEnforcerBase#findRuoliForPersonaInApplication(org.geoserver.security.iride.entity.IrideIdentity, it.csi.iride2.policy.entity.Application)
     */
    @Override
    public IrideRole[] findRuoliForPersonaInApplication(IrideIdentity identity, IrideApplication application) {
        IrideRole[] result = new IrideRole[0];

        final IridePolicy policy = IridePolicy.FIND_RUOLI_FOR_PERSONA_IN_APPLICATION;

        final Map<String, Object> params = new HashMap<>();
        params.put("irideIdentity", identity);
        params.put("application", application);

        try {
            final String policyResponse = this.handleRequest(policy, this.serverURL, params);
            if (StringUtils.isNotBlank(policyResponse)) {
                @SuppressWarnings("unchecked")
                final List<IrideRole> policyResult = (List<IrideRole>) this.handleResponse(policy, policyResponse);

                result = policyResult.toArray(new IrideRole[policyResult.size()]);
            }
        } catch (IOException | TransformerException e) {
            LOGGER.log(Level.SEVERE, String.format(ERROR_MESSAGE_FORMAT, policy.getServiceName(), e.getMessage()), e);
        }

        return result;
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.iride.policy.PolicyEnforcerBase#findRuoliForPersonaInUseCase(org.geoserver.security.iride.entity.IrideIdentity, it.csi.iride2.policy.entity.UseCase)
     */
    @Override
    public IrideRole[] findRuoliForPersonaInUseCase(IrideIdentity identity, IrideUseCase useCase) {
        // TODO: implement...
        return null;
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.iride.policy.PolicyEnforcerBase#findUseCasesForPersonaInApplication(org.geoserver.security.iride.entity.IrideIdentity, it.csi.iride2.policy.entity.Application)
     */
    @Override
    public IrideUseCase[] findUseCasesForPersonaInApplication(IrideIdentity identity, IrideApplication application) {
        // TODO: implement...
        return null;
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.iride.policy.PolicyEnforcerBase#identificaUserPassword(java.lang.String, java.lang.String)
     */
    @Override
    public IrideIdentity identificaUserPassword(String username, String password) {
        // TODO: implement...
        return null;
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.iride.policy.PolicyEnforcerBase#isIdentitaAutentica(org.geoserver.security.iride.entity.IrideIdentity)
     */
    @Override
    public Boolean isIdentitaAutentica(IrideIdentity identity) {
        // TODO: implement...
        return null;
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.iride.policy.PolicyEnforcerBase#isPersonaAutorizzataInUseCase(org.geoserver.security.iride.entity.IrideIdentity, it.csi.iride2.policy.entity.UseCase)
     */
    @Override
    public Boolean isPersonaAutorizzataInUseCase(IrideIdentity identity, IrideUseCase useCase) {
        // TODO: implement...
        return null;
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.iride.policy.PolicyEnforcerBase#isPersonaInRuolo(org.geoserver.security.iride.entity.IrideIdentity, it.csi.iride2.iridefed.entity.IrideRole)
     */
    @Override
    public Boolean isPersonaInRuolo(IrideIdentity identity, IrideRole role) {
        // TODO: implement...
        return null;
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.iride.policy.PolicyEnforcerBase#getInfoPersonaInUseCase(org.geoserver.security.iride.entity.IrideIdentity, it.csi.iride2.policy.entity.UseCase)
     */
    @Override
    public String getInfoPersonaInUseCase(IrideIdentity identity, IrideUseCase useCase) {
        // TODO: implement...
        return null;
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.iride.policy.PolicyEnforcerBase#getInfoPersonaSchema(it.csi.iride2.iridefed.entity.IrideRole)
     */
    @Override
    public String getInfoPersonaSchema(IrideRole role) {
        // TODO: implement...
        return null;
    }

    // === PolicyEnforcerBase interface ===   END =============================

    /**
     *
     * @param policy
     * @param serverURL
     * @param params
     * @return
     * @throws IOException
     */
    private String handleRequest(IridePolicy policy, String serverURL, Map<String, Object> params) throws IOException {
        return this.getPolicyManager().getPolicyRequestHandler(policy).handleRequest(this.serverURL, params);
    }

    /**
     *
     * @param policy
     * @param policyResponse
     * @return
     * @throws TransformerException
     */
    private Object handleResponse(IridePolicy policy, String policyResponse) throws TransformerException {
        return this.getPolicyManager().getPolicyResponseHandler(policy).handleResponse(policyResponse);
    }

}
