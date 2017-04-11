/*
 *  CSI SIRA - Access Manager Security Module ("Rules Engine"), a GeoServer Secure Catalog Resource Access Manager plugin with which specify advanced rules evaluated to decide what the specified user can access.
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
package it.geosolutions.geoserver.sira.security.expression;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static org.apache.commons.lang.StringUtils.isBlank;
import static org.geotools.filter.text.ecql.ECQL.toFilter;
import static org.geotools.util.logging.Logging.getLogger;
import static org.springframework.util.ReflectionUtils.findMethod;
import it.geosolutions.geoserver.sira.security.config.Attributes.Choose.When;
import it.geosolutions.geoserver.sira.security.config.Rule;
import it.geosolutions.geoserver.sira.security.config.SiraAccessManagerConfiguration;
import it.geosolutions.geoserver.sira.security.config.ValidatableConfiguration;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.geoserver.security.AccessMode;
import org.geoserver.security.impl.GeoServerUser;
import org.geoserver.security.iride.entity.IrideInfoPersona;
import org.geoserver.security.iride.util.IrideUserProperties;
import org.geotools.filter.text.cql2.CQLException;
import org.opengis.filter.Filter;
import org.opengis.filter.expression.PropertyName;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.ParserContext;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.core.context.SecurityContextHolder;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;

/**
 * <code>CSI</code> <code>SIRA</code> <code>Access Manager</code>
 * <a href="http://docs.spring.io/spring/docs/3.1.4.RELEASE/spring-framework-reference/html/expressions.html">Spring Expression Language (SpEL)</a> engine.
 *
 * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
 */
public class ExpressionRuleEngine {

    /**
     * Logger.
     */
    private static final Logger LOGGER = getLogger(ExpressionRuleEngine.class);

    private final StandardEvaluationContext evalContext;

    private final ExpressionParser parser;

    /**
     * Constructor.
     */
    public ExpressionRuleEngine() {
        this.evalContext = new StandardEvaluationContext();
        this.parser      = new SpelExpressionParser();
    }

    /**
     * Constructor.
     *
     * @param rootObject
     */
    public ExpressionRuleEngine(Object rootObject) {
        this();

        this.setRootObject(rootObject);
    }

    /**
     * Get the specialized {@link ParserContext}.
     *
     * @return the specialized {@link ParserContext}
     */
    public static ParserContext getTemplateExpression() {
        return ParserContext.TEMPLATE_EXPRESSION;
    }

    /**
     *
     * @param rootObject
     */
    public void setRootObject(Object rootObject) {
        this.evalContext.setRootObject(rootObject);
    }

    /**
     *
     * @param functions
     */
    public void setFunctions(Map<String, Method> functions) {
        checkNotNull(functions, "functions must not be null");

        for (final Entry<String, Method> entry : functions.entrySet()) {
            this.setFunction(entry.getKey(), entry.getValue());
        }
    }

    /**
     *
     * @param name
     * @param method
     */
    public void setFunction(String name, Method method) {
        this.evalContext.registerFunction(name, method);
    }

    /**
     *
     * @param rule
     * @return
     */
    public AccessMode evaluateAccessMode(Rule rule) {
        this.checkRulePreconditions(rule);

        final String result = this.evaluateExpression(rule.getAccessMode(), String.class);
        if (Rule.IGNORERULE.equals(result)) {
            return null;
        } else {
            try {
                return AccessMode.valueOf(result);
            } catch (IllegalArgumentException e) {
                LOGGER.log(Level.SEVERE, e.getMessage());
                throw new IllegalStateException(
                    String.format("rule.accessMode expression must be evaluable as either READ, WRITE or IGNORERULE, but unknown '%s' was evaluated", result), e
                );
            }
        }
    }

    /**
     * Evaluate the given {@link Rule#getFilter()} expression as a valid <code>ECQL</code> query predicate,
     * parsed and returned as an <code>ECQL</code> {@link Filter} instance, equivalent to the constraint specified in the predicate.
     *
     * @param rule the given {@link Rule} which expression is to be evaluated as a valid <code>ECQL</code> query predicate
     * @return the parsed <code>ECQL</code> {@link Filter} instance, equivalent to the constraint specified in the predicate
     * @throws CQLException if the evaluated given {@link Rule#getFilter()} expression is not a valid <code>ECQL</code> query predicate
     */
    public Filter evaluateFilter(Rule rule) throws CQLException {
        this.checkRulePreconditions(rule);

        return toECQLFilter(this.evaluateExpression(rule.getFilter(), String.class));
    }

    /**
     * Evaluate the given {@link When#getFilter()} expression as a valid <code>ECQL</code> query predicate,
     * parsed and returned as an <code>ECQL</code> {@link Filter} instance, equivalent to the constraint specified in the predicate.
     *
     * @param when the given {@link When} condition which filter expression is to be evaluated as a valid <code>ECQL</code> query predicate
     * @return the parsed <code>ECQL</code> {@link Filter} instance, equivalent to the constraint specified in the predicate
     * @throws CQLException if the evaluated given {@link When#getFilter()} expression is not a valid <code>ECQL</code> query predicate
     */
    public Filter evaluateFilter(When when) throws CQLException {
        this.checkRulePreconditions(when);

        return toECQLFilter(this.evaluateExpression(when.getFilter(), String.class));
    }

    /**
     *
     * @param rule
     * @return
     */
    public List<PropertyName> evaluateHiddenProperties(Rule rule) {
        this.checkRulePreconditions(rule);

        // consider attributes that are to be always hidden, if any...
        final List<PropertyName> hiddenProperties = Lists.newArrayList();
        for (final String defaultHiddenAttribute : rule.getHiddenAttributes().getDefaultAttributes()) {
            hiddenProperties.add(SiraAccessManagerConfiguration.FF.property(defaultHiddenAttribute));
        }

        return hiddenProperties;
    }

    /**
     *
     * @param filter
     * @return
     * @throws CQLException
     */
    private static Filter toECQLFilter(String filter) throws CQLException {
        return toFilter(filter, SiraAccessManagerConfiguration.FF);
    }

    /**
     * Check that the preconditions are met for the given {@link ValidatableConfiguration} instance.
     *
     * @param configuration the given {@link ValidatableConfiguration} instance
     * @throws NullPointerException if the given {@link ValidatableConfiguration} instance is {@code null}
     * @throws IllegalArgumentException if the given {@link ValidatableConfiguration} instance is not valid
     */
    private void checkRulePreconditions(ValidatableConfiguration configuration) {
        checkNotNull(configuration, "configuration must not be null");
        checkArgument(configuration.isValid(), "configuration must be valid, given: " + configuration);
    }

    /**
     *
     * @param expressionString
     * @param expectedResultType
     * @return
     */
    private <T> T evaluateExpression(String expressionString, Class<T> expectedResultType) {
        final Expression expression = this.parser.parseExpression(expressionString, getTemplateExpression());

        return expression.getValue(this.evalContext, expectedResultType);
    }

    /**
     * <code>CSI</code> <code>SIRA</code> <code>Access Manager</code>
     * <a href="http://docs.spring.io/spring/docs/3.1.4.RELEASE/spring-framework-reference/html/expressions.html">Spring Expression Language (SpEL)</a> engine
     * custom functions.
     *
     * @author "Simone Cornacchia - seancrow76@gmail.com, simone.cornacchia@consulenti.csi.it (CSI:71740)"
     */
    public static final class Functions {

        /**
         * Exported, immutable map of method name/{@link Method} instance pairs usable as {@link ExpressionRuleEngine#setFunctions(Map)} parameter, to register expression engine custom functions.
         * <p>Builtin custom functions:
         * <ul>
         *   <li>if : {@link #iif(boolean, Object, Object)}</li>
         *   <li>hasAuthority : {@link #hasAuthority(String, String)}</li>
         *   <li>hasIstatProvincia : {@link #hasIstatProvincia(String, String)}</li>
         *   <li>hasIstatComune : {@link #hasIstatComune(String, String)}</li>
         * <ul>
         */
        public static final Map<String, Method> BUILTINS = ImmutableMap.of(
            "if", findMethod(
            Functions.class, "iif", new Class<?>[] {
                boolean.class, Object.class, Object.class
            }),
            "hasAuthority", findMethod(
            Functions.class, "hasAuthority", new Class<?>[] {
                String.class, String.class
            }),
            "hasIstatProvincia", findMethod(
            Functions.class, "hasIstatProvincia", new Class<?>[] {
                String.class, String.class
            }),
            "hasIstatComune", findMethod(
            Functions.class, "hasIstatComune", new Class<?>[] {
                String.class, String.class
            })
        );

        /**
         * Constructor.
         */
        private Functions() {
            /* NOP */
        }

        /**
         * A <code>Java</code> implementation of the <a href="https://msdn.microsoft.com/en-us/library/27ydhh0d(v=vs.90).aspx">Visual Basic <code>iif()</code> function</a>.
         *
         * <p>Returns one of two objects, <code>truthPart</code> or <code>falsePart</code>, depending on the evaluation of the given <code>expression</code>.
         *
         * <p>Similarly to <code>iif()</code> function (and contrary to <code>Java</code> native <code>ternary operator</code>),
         * <em>both</em> the returned and the unreturned values got evaluated, at call time,
         * while the <code>Java</code> native <code>ternary operator</code> short-circuits evaluating only the object actually returned.
         * <p>Therefore if there are side-effects to the evaluation, <code>iif()</code>
         * and <code>Java</code> native <code>ternary operator</code> are <em>not</em> equivalent.
         *
         * @param expression the given expression to evaluate
         * @param truePart object returned if <code>expression</code> evaluates to {@code true}
         * @param falsePart object returned if <code>expression</code> evaluates to {@code false}
         * @return one of two objects, depending on the evaluation of an <code>expression</code>
         */
        public static <T> T iif(boolean expression, T truePart, T falsePart) {
            return expression ? truePart : falsePart;
        }

        /**
         * Check to see if the given <code>ID_AUTORITA</code> {@code value} is present
         * in authenticated user's {@link IrideInfoPersona}s, for the given <code>IRIDE</code> {@code role},
         * returning {@code true} if found, {@code false} otherwise.
         *
         * @param role the given <code>IRIDE</code> {@code role}
         * @param value the given property {@code value}
         * @return {@code true} if the given <code>ID_AUTORITA</code> {@code value} is found
         *         in authenticated user's {@link IrideInfoPersona}s, for the given <code>IRIDE</code> {@code role},
         *         {@code false} otherwise.
         */
        public static boolean hasAuthority(String role, String value) {
            return hasInfoPersonaProperty(role, "ID_AUTORITA", value);
        }

        /**
         * Check to see if the given <code>ISTAT_PROVINCIA</code> {@code value} is present
         * in authenticated user's {@link IrideInfoPersona}s, for the given <code>IRIDE</code> {@code role},
         * returning {@code true} if found, {@code false} otherwise.
         *
         * @param role the given <code>IRIDE</code> {@code role}
         * @param value the given property {@code value}
         * @return {@code true} if the given <code>ISTAT_PROVINCIA</code> {@code value} is found
         *         in authenticated user's {@link IrideInfoPersona}s, for the given <code>IRIDE</code> {@code role},
         *         {@code false} otherwise.
         */
        public static boolean hasIstatProvincia(String role, String value) {
            return hasInfoPersonaProperty(role, "ISTAT_PROVINCIA", value);
        }

        /**
         * Check to see if the given <code>ISTAT_COMUNE</code> {@code value} is present
         * in authenticated user's {@link IrideInfoPersona}s, for the given <code>IRIDE</code> {@code role},
         * returning {@code true} if found, {@code false} otherwise.
         *
         * @param role the given <code>IRIDE</code> {@code role}
         * @param value the given property {@code value}
         * @return {@code true} if the given <code>ISTAT_COMUNE</code> {@code value} is found
         *         in authenticated user's {@link IrideInfoPersona}s, for the given <code>IRIDE</code> {@code role},
         *         {@code false} otherwise.
         */
        public static boolean hasIstatComune(String role, String value) {
            return hasInfoPersonaProperty(role, "ISTAT_COMUNE", value);
        }

        /**
         * Check to see if the given property ({@code key}) {@code value} is present
         * in authenticated user's {@link IrideInfoPersona}s, for the given <code>IRIDE</code> {@code role},
         * returning {@code true} if found, {@code false} otherwise.
         *
         * @param role the given <code>IRIDE</code> {@code role}
         * @param key the given property {@code key}
         * @param value the given property {@code value}
         * @return {@code true} if the given property ({@code key}) {@code value} is found
         *         in authenticated user's {@link IrideInfoPersona}s, for the given <code>IRIDE</code> {@code role},
         *         {@code false} otherwise.
         */
        private static boolean hasInfoPersonaProperty(String role, String key, String value) {
            if (isBlank(role) || isBlank(key) || isBlank(value)) {
                return false;
            }

            final Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            final Set<IrideInfoPersona> infoPersonae = getInfoPersonae((GeoServerUser) principal);
            for (final IrideInfoPersona ip : infoPersonae) {
                if (ip.getRole().getCode().equals(role)) {
                    final Map<String, Object> properties = ip.getProperties();
                    if (value.equals(properties.get(key))) {
                        return true;
                    }
                }
            }

            return false;
        }

        /**
         * Extracts the given {@link GeoServerUser} instance's {@link IrideInfoPersona}s.
         * If none are found, an empty, immutable set is returned.
         *
         * @param user the given {@link GeoServerUser} instance to extract {@link IrideInfoPersona}s from.
         * @return the given {@link GeoServerUser} instance's {@link IrideInfoPersona}s,
         *         or an empty, immutable set if none are found.
         */
        @SuppressWarnings("unchecked")
        private static Set<IrideInfoPersona> getInfoPersonae(GeoServerUser user) {
            final Properties properties = user.getProperties();
            if (properties.containsKey(IrideUserProperties.INFO_PERSONAE)) {
                return (Set<IrideInfoPersona>) properties.get(IrideUserProperties.INFO_PERSONAE);
            }

            return ImmutableSet.of();
        }

    }

}
