/*
 *    GeoTools - The Open Source Java GIS Toolkit
 *    http://geotools.org
 *
 *    (C) 2002-2011, Open Source Geospatial Foundation (OSGeo)
 *
 *    This library is free software; you can redistribute it and/or
 *    modify it under the terms of the GNU Lesser General Public
 *    License as published by the Free Software Foundation;
 *    version 2.1 of the License.
 *
 *    This library is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *    Lesser General Public License for more details.
 */
package org.geoserver.security.iride;

import static org.geoserver.security.iride.util.builder.ToStringReflectionBuilder.reflectToString;

import org.geoserver.security.GeoServerRoleService;
import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.config.BaseSecurityNamedServiceConfig;
import org.geoserver.security.config.SecurityAuthProviderConfig;
import org.geoserver.security.config.SecurityRoleServiceConfig;

/**
 * <code>GeoServer</code> <code>IRIDE</code> Security Provider configuration.
 *
 * @author "Mauro Bartolomeoli - mauro.bartolomeoli@geo-solutions.it"
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 *
 */
public class IrideSecurityServiceConfig extends BaseSecurityNamedServiceConfig implements SecurityAuthProviderConfig, SecurityRoleServiceConfig {

    private static final long serialVersionUID = -8931342487350680340L;

    /**
     * <code>IRIDE</code> server <code>URL</code>.
     */
    private String serverURL;

    /**
     * Name of the application requesting <code>IRIDE</code> service.
     *
     * @todo should be set dynamically at runtime
     */
    private String applicationName;

    /**
     * Admin role.
     * Used for both <code>admin role name</code> and <code>group admin role name</code>.
     */
    private String adminRole;

    /**
     * Name of the {@link GeoServerRoleService} to rely on as a fallback
     * when {@link IrideRoleService} does not found any roles for a given user.
     */
    private String fallbackRoleService;

    /**
     * Constructor.
     */
    public IrideSecurityServiceConfig() {
        /* NOP */
    }

    /**
     * Constructor. <p>
     * Copy constructor receiving another {@link IrideSecurityServiceConfig} instance. <br />
     * Needed by <code>GeoServer</code>.
     *
     * @param other the other {@link IrideSecurityServiceConfig} instance to copy from
     */
    public IrideSecurityServiceConfig(IrideSecurityServiceConfig other) {
        super(other);

        this.serverURL           = other.getServerURL();
        this.applicationName     = other.getApplicationName();
        this.adminRole           = other.getAdminRole();
        this.fallbackRoleService = other.getFallbackRoleService();
    }

    /**
     * Returns the <code>IRIDE</code> server <code>URL</code>.
     *
     * @return the <code>IRIDE</code> server <code>URL</code>
     */
    public String getServerURL() {
        return this.serverURL;
    }

    /**
     * Set the <code>IRIDE</code> server <code>URL</code>.
     *
     * @param serverURL <code>IRIDE</code> server <code>URL</code>
     */
    public void setServerURL(String serverURL) {
        this.serverURL = serverURL;
    }

    /**
     * Returns the name of the application requesting <code>IRIDE</code> service.
     *
     * @return the name of the application requesting <code>IRIDE</code> service
     */
    public String getApplicationName() {
        return this.applicationName;
    }

    /**
     * Set the name of the application requesting <code>IRIDE</code> service.
     *
     * @param applicationName the name of the application requesting <code>IRIDE</code> service
     */
    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }

    /**
     * Returns the admin role.
     * Used for both <code>admin role name</code> and <code>group admin role name</code>.
     *
     * @return the adminRole
     */
    public String getAdminRole() {
        return this.adminRole;
    }

    /**
     * Set the admin role.
     * Used for both <code>admin role name</code> and <code>group admin role name</code>.
     *
     * @param adminRole the adminRole
     */
    public void setAdminRole(String adminRole) {
        this.adminRole = adminRole;
    }

    /**
     * Returns the name of the {@link GeoServerRoleService} to rely on as a fallback
     * when {@link IrideRoleService} does not found any roles for a given user.
     *
     * @return the name of the {@link GeoServerRoleService} to rely on as a fallback
     *         when {@link IrideRoleService} does not found any roles for a given user
     */
    public String getFallbackRoleService() {
        return this.fallbackRoleService;
    }

    /**
     * Set the name of the {@link GeoServerRoleService} to rely on as a fallback
     * when {@link IrideRoleService} does not found any roles for a given user.
     *
     * @param fallbackRoleService the name of the {@link GeoServerRoleService} to rely on as a fallback
     *        when {@link IrideRoleService} does not found any roles for a given user
     */
    public void setFallbackRoleService(String fallbackRoleService) {
        this.fallbackRoleService = fallbackRoleService;
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.config.SecurityRoleServiceConfig#getAdminRoleName()
     */
    /**
     * @see {@link #getAdminRole()}.
     */
    @Override
    public String getAdminRoleName() {
        return this.getAdminRole();
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.config.SecurityRoleServiceConfig#setAdminRoleName(java.lang.String)
     */
    /**
     * @see #setAdminRole(String)
     */
    @Override
    public void setAdminRoleName(String adminRoleName) {
        this.setAdminRole(adminRoleName);
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.config.SecurityRoleServiceConfig#getGroupAdminRoleName()
     */
    /**
     * @see {@link #getAdminRole()}.
     */
    @Override
    public String getGroupAdminRoleName() {
        return this.getAdminRole();
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.config.SecurityRoleServiceConfig#setGroupAdminRoleName(java.lang.String)
     */
    /**
     * @see #setAdminRole(String)
     */
    @Override
    public void setGroupAdminRoleName(String adminRoleName) {
        this.setAdminRole(adminRoleName);
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.config.SecurityAuthProviderConfig#getUserGroupServiceName()
     */
    /**
     * No {@link GeoServerUserGroupService} needed, returning {@code null}.
     */
    @Override
    public String getUserGroupServiceName() {
        return null;
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.config.SecurityAuthProviderConfig#setUserGroupServiceName(java.lang.String)
     */
    /**
     * No {@link GeoServerUserGroupService} needed, nothing to do.
     */
    @Override
    public void setUserGroupServiceName(String userGroupServiceName) {
        /* NOP */
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.config.BaseSecurityNamedServiceConfig#toString()
     */
    @Override
    public String toString() {
        return reflectToString(this);
    }

}
