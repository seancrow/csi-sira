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
package org.geoserver.security.iride.util.object;

import java.io.Serializable;
import java.util.Map;

/**
 * Registry class for objects.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 *
 * @param <I>
 * @param <O>
 */
public abstract class ObjectRegistry<I extends Serializable, O extends RegistrableObject<I>> {

    /**
     * Registered available objects.
     */
    protected final Map<I, O> objects;

    /**
     * Constructor.
     */
    protected ObjectRegistry() {
        this.objects = this.initObjects();
    }

    /**
     * Constructor.
     *
     * @param objects objects to register
     */
    protected ObjectRegistry(O[] objects) {
        this();

        this.register(objects);
    }

    /**
     * Returns {@code true} if the given object is contained by this registry:
     * i.e. there is an object indexed by the given objectId, {@code false} otherwise.
     *
     * @param objectId the given objectId
     * @return {@code true} if the given object is contained by this registry:
     *         i.e. there is an object indexed by the given objectId, {@code false} otherwise
     */
    public final boolean contains(I objectId) {
        return this.objects.containsKey(objectId);
    }

    /**
     * Returns the registered object indexed by the given objectId,
     * or {@code null} if no object is found for the the given objectId.
     *
     * @param objectId the given objectId
     * @return the registered object indexed by the given objectId,
     *         or {@code null} if no object is found for the the given objectId
     */
    public final O lookup(I objectId) {
        return this.objects.get(objectId);
    }

    /**
     * Registers the given objects, indexed by theirs objectIds.
     *
     * @param objects objects to register
     */
    protected void register(O[] objects) {
        for (final O object : objects) {
            this.register(object);
        }
    }

    /**
     * Registers the given object, indexed by its objectId.
     *
     * @param object object to register
     */
    protected void register(O object) {
        final I objectId = object.getObjectId();

        this.objects.put(objectId, object);
    }

    /**
     * Initialize the internal map serving as objects registry
     *
     * @return the internal map properly initialized
     */
    protected abstract Map<I, O> initObjects();

}
