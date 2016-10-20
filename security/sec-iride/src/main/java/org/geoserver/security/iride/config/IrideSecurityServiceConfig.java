/*
 *  GeoServer Security Provider plugin used for doing authentication and authorization operations using CSI-Piemonte IRIDE Service.
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
package org.geoserver.security.iride.config;

import static org.geoserver.security.iride.util.builder.util.ToStringReflectionBuilder.reflectToString;

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
public final class IrideSecurityServiceConfig extends BaseSecurityNamedServiceConfig implements SecurityAuthProviderConfig, SecurityRoleServiceConfig {

    private static final long serialVersionUID = -8931342487350680340L;

    /**
     * <code>IRIDE</code> server <code>URL</code>.
     */
    private String serverURL;

    /**
     * Application name requesting <code>IRIDE</code> service.
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
     * Name of the {@link GeoServerUserGroupService} to use.
     */
    private String userGroupServiceName;

    /**
     * Constructor.
     */
    public IrideSecurityServiceConfig() {
        /* NOP */
    }

    /**
     * Constructor.<p>
     * Copy constructor receiving another {@link IrideSecurityServiceConfig} instance.
     * <em>Needed by <code>GeoServer</code></em>.
     *
     * @param other the other {@link IrideSecurityServiceConfig} instance to copy from
     */
    public IrideSecurityServiceConfig(IrideSecurityServiceConfig other) {
        super(other);

        this.serverURL            = other.getServerURL();
        this.applicationName      = other.getApplicationName();
        this.adminRole            = other.getAdminRole();
        this.fallbackRoleService  = other.getFallbackRoleService();
        this.userGroupServiceName = other.getUserGroupServiceName();
    }

    /**
     * @return the serverURL
     */
    public String getServerURL() {
        return this.serverURL;
    }

    /**
     * @param serverURL the serverURL to set
     */
    public void setServerURL(String serverURL) {
        this.serverURL = serverURL;
    }

    /**
     * @return the applicationName
     */
    public String getApplicationName() {
        return this.applicationName;
    }

    /**
     * @param applicationName the applicationName to set
     */
    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }

    /**
     * @return the adminRole
     */
    public String getAdminRole() {
        return this.adminRole;
    }

    /**
     * @param adminRole the adminRole to set
     */
    public void setAdminRole(String adminRole) {
        this.adminRole = adminRole;
    }

    /**
     *
     * @return
     */
    public String getFallbackRoleService() {
        return this.fallbackRoleService;
    }

    /**
     *
     * @param fallbackRoleService
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
     * Return the name of the {@link GeoServerUserGroupService} to use.
     */
    @Override
    public String getUserGroupServiceName() {
        return this.userGroupServiceName;
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.config.SecurityAuthProviderConfig#setUserGroupServiceName(java.lang.String)
     */
    /**
     * Set the name of the {@link GeoServerUserGroupService} to use.
     */
    @Override
    public void setUserGroupServiceName(String userGroupServiceName) {
        this.userGroupServiceName = userGroupServiceName;
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
