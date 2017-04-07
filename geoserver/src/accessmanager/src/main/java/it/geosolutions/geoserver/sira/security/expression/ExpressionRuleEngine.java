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

import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.lang.StringUtils;
import org.geoserver.security.AccessMode;
import org.geoserver.security.impl.GeoServerUser;
import org.geoserver.security.iride.entity.IrideInfoPersona;
import org.geoserver.security.iride.util.IrideUserProperties;
import org.geotools.filter.text.cql2.CQLException;
import org.geotools.filter.text.ecql.ECQL;
import org.geotools.util.logging.Logging;
import org.opengis.filter.Filter;
import org.opengis.filter.expression.PropertyName;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.ParserContext;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.ReflectionUtils;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

import it.geosolutions.geoserver.sira.security.config.Attributes.Choose.When;
import it.geosolutions.geoserver.sira.security.config.Rule;
import it.geosolutions.geoserver.sira.security.config.SiraAccessManagerConfiguration;
import it.geosolutions.geoserver.sira.security.config.ValidatableConfiguration;

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
    private static final Logger LOGGER = Logging.getLogger(ExpressionRuleEngine.class);

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
        Preconditions.checkNotNull(functions, "functions must not be null");

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
        return ECQL.toFilter(filter, SiraAccessManagerConfiguration.FF);
    }

    /**
     * Check that the preconditions are met for the given {@link ValidatableConfiguration} instance.
     *
     * @param configuration the given {@link ValidatableConfiguration} instance
     * @throws NullPointerException if the given {@link ValidatableConfiguration} instance is {@code null}
     * @throws IllegalArgumentException if the given {@link ValidatableConfiguration} instance is not valid
     */
    private void checkRulePreconditions(ValidatableConfiguration configuration) {
        Preconditions.checkNotNull(configuration, "configuration must not be null");
        Preconditions.checkArgument(configuration.isValid(), "configuration must be valid, given: " + configuration);
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
         * Inner map of method name/{@link Method} instance pairs.
         */
        private static final Map<String, Method> _BUILTINS = Maps.newHashMap();
        static {
            _BUILTINS.put("if", ReflectionUtils.findMethod(
                Functions.class, "iif", new Class<?>[] {
                    boolean.class, Object.class, Object.class
                }
            ));
            _BUILTINS.put("hasAuthority", ReflectionUtils.findMethod(
                Functions.class, "hasAuthority", new Class<?>[] {
                    IrideInfoPersona.class, String.class
                }
            ));
        }

        /**
         * Exported, immutable map of method name/{@link Method} instance pairs usable as {@link ExpressionRuleEngine#setFunctions(Map)} parameter, to register expression engine "functions".
         * <p>"Functions":
         * <ul>
         *   <li>if : {@link #iif(boolean, Object, Object)}</li>
         *   <li>hasAuthority : {@link #hasAuthority(String, String, String)}</li>
         * <ul>
         */
        public static final Map<String, Method> BUILTINS = ImmutableMap.<String, Method>copyOf(_BUILTINS);

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
         *
         * @param role
         * @param key
         * @param value
         * @return 
         */
        public static boolean hasAuthority(String role, String key, String value) {
            if (StringUtils.isBlank(role) || StringUtils.isBlank(key) || StringUtils.isBlank(value)) {
                return false;
            }

            Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            if (principal instanceof GeoServerUser) {
                IrideInfoPersona[] infoPersonae = getInfoPersonae((GeoServerUser) principal);
                if (infoPersonae == null) {
                    return false;
                }

                for (IrideInfoPersona ip : infoPersonae) {
                    if (ip == null || !role.equals(ip.getRole().getCode())) {
                        continue;
                    }

                    Map<String, Object> properties = ip.getProperties();
                    if (properties != null && value.equals(properties.get(key))) {
                        return true;
                    }
                }
            }

            return false;
        }

        /**
        * 
        * @param role
        * @param value
        * @return
        */
        public static boolean hasIstatProvincia(String role, String value) {
            final String KEY = "ISTAT_PROVINCIA";
            return hasAuthority(role, KEY, value);
        }

        /**
        * 
        * @param role
        * @param value
        * @return
        */
        public static boolean hasIstatComune(String role, String value) {
            final String KEY = "ISTAT_COMUNE";
            return hasAuthority(role, KEY, value);
        }

        private static IrideInfoPersona[] getInfoPersonae(GeoServerUser user) {
            Properties properties = user.getProperties();
            if (properties != null && properties.containsKey(IrideUserProperties.INFO_PERSONAE)) {
                return (IrideInfoPersona[]) properties.get(IrideUserProperties.INFO_PERSONAE);
            }

            return null;
        }

    }

}
