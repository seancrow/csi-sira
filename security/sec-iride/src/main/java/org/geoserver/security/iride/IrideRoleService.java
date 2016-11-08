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
package org.geoserver.security.iride;

import java.io.IOException;
import java.util.Map;
import java.util.Properties;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.lang.StringUtils;
import org.geoserver.security.GeoServerRoleService;
import org.geoserver.security.GeoServerRoleStore;
import org.geoserver.security.GeoServerUserGroupStore;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.event.RoleLoadedListener;
import org.geoserver.security.impl.AbstractGeoServerSecurityService;
import org.geoserver.security.impl.GeoServerRole;
import org.geoserver.security.iride.config.IrideRoleServiceConfig;
import org.geoserver.security.iride.entity.IrideApplication;
import org.geoserver.security.iride.entity.IrideIdentity;
import org.geoserver.security.iride.entity.IrideRole;
import org.geoserver.security.iride.service.IrideService;
import org.geoserver.security.iride.service.IrideServiceAware;
import org.geoserver.security.iride.util.logging.LoggerProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSortedSet;

/**
 * <code>GeoServer</code> <code>IRIDE</code> <a href="http://docs.geoserver.org/stable/en/user/security/usergrouprole/roleservices.html">Role Service</a>,
 * backed by <a href="http://www.csipiemonte.it/">CSI</a> <code>IRIDE</code> service.
 * <p><code>IRIDE</code> Role Service is <em>read-only</em>, therefore <em>there is no support for {@link GeoServerUserGroupStore} usage</em>:
 * {@link #canCreateStore()} will return {@code false} and {@link #createStore()} will return {@code null}.
 *
 * @author "Mauro Bartolomeoli - mauro.bartolomeoli@geo-solutions.it"
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public class IrideRoleService extends AbstractGeoServerSecurityService implements GeoServerRoleService, IrideServiceAware {

    /**
     * Logger.
     */
    private static final Logger LOGGER = LoggerProvider.SECURITY.getLogger();

    /**
     * {@link IrideRoleService} configuration object.
     */
    private Config config;

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

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.impl.AbstractGeoServerSecurityService#initializeFromConfig(org.geoserver.security.config.SecurityNamedServiceConfig)
     */
    @Override
    public void initializeFromConfig(SecurityNamedServiceConfig config) throws IOException {
        LOGGER.log(Level.INFO,
            "Initializing {0} with configuration object: \n\t {1}",
            new Object[] { this.getClass().getSimpleName(), config }
        );

        this.name   = config.getName();
        this.config = new Config(config);

        this.getIrideService().initializeFromConfig(config);
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.GeoServerRoleService#getGroupNamesForRole(org.geoserver.security.impl.GeoServerRole)
     */
    /**
     * Returns an immutable empty {@link ImmutableSortedSet} instance.
     */
    @Override
    public SortedSet<String> getGroupNamesForRole(GeoServerRole role) throws IOException {
        LOGGER.info("Role: " + role);

        return ImmutableSortedSet.of();
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.GeoServerRoleService#getUserNamesForRole(org.geoserver.security.impl.GeoServerRole)
     */
    /**
     * Returns an immutable empty {@link ImmutableSortedSet} instance.
     */
    @Override
    public SortedSet<String> getUserNamesForRole(GeoServerRole role) throws IOException {
        LOGGER.info("Role: " + role);

        return ImmutableSortedSet.of();
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.GeoServerRoleService#getRolesForUser(java.lang.String)
     */
    @Override
    public SortedSet<GeoServerRole> getRolesForUser(final String username) throws IOException {
        LOGGER.info("User: " + username);

        final TreeSet<GeoServerRole> roles = new TreeSet<>();

        final IrideIdentity irideIdentity = IrideIdentity.parseIrideIdentity(username);
        if (irideIdentity != null) {
            final IrideRole[] irideRoles = this.getIrideService().findRuoliForPersonaInApplication(
                irideIdentity,
                new IrideApplication(this.config.applicationName)
            );
            for (final IrideRole irideRole : irideRoles) {
                roles.add(this.createRoleObject(irideRole.toMnemonicRepresentation()));
            }
        }

        // Rely on the fallback RoleService (if configured) when no IRIDE roles are available for the given user
        if (roles.isEmpty() && this.config.hasFallbackRoleServiceName()) {
            LOGGER.info("No IRIDE roles available for the given user " + username + ": falling back to RoleService '" + this.config.fallbackRoleServiceName + "'");

            final GeoServerRoleService fallbackRoleService = this.getSecurityManager().loadRoleService(this.config.fallbackRoleServiceName);
            if (fallbackRoleService != null) {
                roles.addAll(fallbackRoleService.getRolesForUser(username));
            } else {
                LOGGER.warning("A fallback RoleService '" + this.config.fallbackRoleServiceName + "' was specified, but none was found!");
            }
        }

        LOGGER.info("Added " + roles.size() + " roles for User " + username);

        return ImmutableSortedSet.copyOf(roles);
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.GeoServerRoleService#getUserNamesForRole(org.geoserver.security.impl.GeoServerRole)
     */
    /**
     * Returns an immutable empty {@link ImmutableSortedSet} instance.
     */
    @Override
    public SortedSet<GeoServerRole> getRolesForGroup(String groupname) throws IOException {
        LOGGER.info("Group: " + groupname);

        return ImmutableSortedSet.of();
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.GeoServerRoleService#getUserNamesForRole(org.geoserver.security.impl.GeoServerRole)
     */
    /**
     * Returns an immutable empty {@link ImmutableSortedSet} instance.
     */
    @Override
    public SortedSet<GeoServerRole> getRoles() throws IOException {
        return ImmutableSortedSet.of();
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.GeoServerRoleService#getUserNamesForRole(org.geoserver.security.impl.GeoServerRole)
     */
    /**
     * Returns an immutable empty {@link ImmutableMap} instance.
     */
    @Override
    public Map<String, String> getParentMappings() throws IOException {
        return ImmutableMap.of();
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.GeoServerRoleService#createRoleObject(java.lang.String)
     */
    @Override
    public GeoServerRole createRoleObject(String role) throws IOException {
        LOGGER.info("Role: " + role);

        return new GeoServerRole(role);
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.GeoServerRoleService#getParentRole(org.geoserver.security.impl.GeoServerRole)
     */
    @Override
    public GeoServerRole getParentRole(GeoServerRole role) throws IOException {
        LOGGER.info("Role: " + role);

        return null;
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.GeoServerRoleService#getRoleByName(java.lang.String)
     */
    @Override
    public GeoServerRole getRoleByName(String role) throws IOException {
        LOGGER.info("Role: " + role);

        return null;
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.GeoServerRoleService#load()
     */
    @Override
    public void load() throws IOException {
        /* NOP */
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.GeoServerRoleService#personalizeRoleParams(java.lang.String, java.util.Properties, java.lang.String, java.util.Properties)
     */
    @Override
    public Properties personalizeRoleParams(String roleName, Properties roleParams, String userName, Properties userProps) throws IOException {
        LOGGER.log(Level.INFO,
            "\n\t Role: {0},\n\t Role Params: {1},\n\t User: {2},\n\t User Properties: {3}",
            new Object[] { roleName, roleParams, userName, userProps }
        );

        return null;
    }

    // TODO: review this method!
    /*
     * (non-Javadoc)
     * @see org.geoserver.security.GeoServerRoleService#getAdminRole()
     */
    @Override
    public GeoServerRole getAdminRole() {
        // TODO: temp code!
        String username = null;
        final SecurityContext context = SecurityContextHolder.getContext();
        final Authentication authentication = context.getAuthentication();
        if (authentication != null) {
            username = String.valueOf(authentication.getPrincipal());
        }
        // ~

        LOGGER.info("AdminRole Username: " + username);

        GeoServerRole role = null;
        try {
            // Check username format: it may be an Identita Digitale IRIDE, or not
            if (IrideIdentity.isNotValidIrideIdentity(username) && this.config.hasFallbackRoleServiceName()) {
                LOGGER.info("Username " + username + " is not a valid IRIDE Identity: falling back to RoleService '" + this.config.fallbackRoleServiceName + "'");

                final GeoServerRoleService fallbackRoleService = this.getSecurityManager().loadRoleService(this.config.fallbackRoleServiceName);
                if (fallbackRoleService != null) {
                    role = fallbackRoleService.getAdminRole();

                    LOGGER.info("Role: " + role.getAuthority());
                } else {
                    LOGGER.warning("A fallback RoleService '" + this.config.fallbackRoleServiceName + "' was specified, but none was found!");
                }
            } else {
                role = this.createRoleObject(this.config.adminRole);
            }

            return role;
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, e.getMessage(), e);

            return null;
        }
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.GeoServerRoleService#getGroupAdminRole()
     */
    /**
     * @see {@link #getAdminRole()}
     */
    @Override
    public GeoServerRole getGroupAdminRole() {
        return this.getAdminRole();
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.GeoServerRoleService#getRoleCount()
     */
    @Override
    public int getRoleCount() throws IOException {
        return 0;
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.GeoServerRoleService#createStore()
     */
    @Override
    public GeoServerRoleStore createStore() throws IOException {
        return null;
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.GeoServerRoleService#registerRoleLoadedListener(org.geoserver.security.event.RoleLoadedListener)
     */
    @Override
    public void registerRoleLoadedListener(RoleLoadedListener listener) {
        /* NOP */
    }

    /*
     * (non-Javadoc)
     * @see org.geoserver.security.GeoServerRoleService#unregisterRoleLoadedListener(org.geoserver.security.event.RoleLoadedListener)
     */
    @Override
    public void unregisterRoleLoadedListener(RoleLoadedListener listener) {
        /* NOP */
    }

    /**
     * {@link IrideRoleService} configuration.
     *
     * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
     */
    private static final class Config {

        /**
         * Application name requesting <code>IRIDE</code> service.
         *
         * @todo should be set dynamically at runtime
         */
        private final String applicationName;

        /**
         * Admin role.
         * Used for both <code>admin role name</code> and <code>group admin role name</code>.
         */
        private final String adminRole;

        /**
         * Name of the {@link GeoServerRoleService} to rely on as a fallback
         * when {@link IrideRoleService} does not found any roles for a given user.
         */
        private final String fallbackRoleServiceName;

        /**
         * Constructor.
         *
         * Initialize a {@link Config} object from a {@link SecurityNamedServiceConfig} instance.
         *
         * @param cfg a {@link SecurityNamedServiceConfig} instance
         * @throws IllegalStateException if the {@link #applicationName} or the {@link #adminRole} are not deemed valid:
         *                               a valid {@link #applicationName} or {@link #adminRole} must be <em>non-blank</em>,
         *                               as per {@link StringUtils#isNotBlank(String)} check rules.
         */
        Config(SecurityNamedServiceConfig cfg) {
            Preconditions.checkArgument(cfg instanceof IrideRoleServiceConfig, "Config object must be of IrideRoleServiceConfig type");

            final IrideRoleServiceConfig irideCfg = (IrideRoleServiceConfig) cfg;

            this.applicationName         = irideCfg.getApplicationName();
            this.adminRole               = irideCfg.getAdminRole();
            this.fallbackRoleServiceName = StringUtils.trimToNull(irideCfg.getFallbackRoleService());

            Preconditions.checkState(StringUtils.isNotBlank(this.applicationName), "Application name must not be of an empty string");
            Preconditions.checkState(StringUtils.isNotBlank(this.adminRole), "Admin role must not be of an empty string");
        }

        /**
         * Returns {@code true} if a fallback {@link GeoServerRoleService} name has been defined, {@code false} otherwise.
         *
         * @return {@code true} if a fallback {@link GeoServerRoleService} name has been defined, {@code false} otherwise
         */
        boolean hasFallbackRoleServiceName() {
            return this.fallbackRoleServiceName != null;
        }

    }

}
