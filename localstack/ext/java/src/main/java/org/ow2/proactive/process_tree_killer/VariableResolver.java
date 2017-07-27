/*
 * ProActive Parallel Suite(TM):
 * The Open Source library for parallel and distributed
 * Workflows & Scheduling, Orchestration, Cloud Automation
 * and Big Data Analysis on Enterprise Grids & Clouds.
 *
 * Copyright (c) 2007 - 2017 ActiveEon
 * Contact: contact@activeeon.com
 *
 * This library is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation: version 3 of
 * the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * If needed, contact us to obtain a release under GPL Version 2 or 3
 * or a different license than the AGPL.
 */
package org.ow2.proactive.process_tree_killer;

import java.util.Collection;
import java.util.Map;


/**
 * Resolves variables to its value, while encapsulating
 * how that resolution happens.
 *
 * @author Kohsuke Kawaguchi
 */
@SuppressWarnings("all")
public interface VariableResolver<V> {
    /**
     * Receives a variable name and obtains the value associated with the name.
     *
     * <p>
     * This can be implemented simply on top of a {@link Map} (see {@link ByMap}), or
     * this can be used like an expression evaluator.
     *
     * @param name
     *      Name of the variable to be resolved.
     *      Never null, never empty. The name shouldn't include the syntactic
     *      marker of an expression. IOW, it should be "foo" but not "${foo}".
     *      A part of the goal of this design is to abstract away the expression
     *      marker syntax. 
     * @return
     *      Object referenced by the name.
     *      Null if not found.
     */
    V resolve(String name);

    /**
     * Empty resolver that always returns null.
     */
    VariableResolver NONE = new VariableResolver() {
        public Object resolve(String name) {
            return null;
        }
    };

    /**
     * {@link VariableResolver} backed by a {@link Map}.
     */
    final class ByMap<V> implements VariableResolver<V> {
        private final Map<String, V> data;

        public ByMap(Map<String, V> data) {
            this.data = data;
        }

        public V resolve(String name) {
            return data.get(name);
        }
    }

    /**
     * Union of multiple {@link VariableResolver}.
     */
    final class Union<V> implements VariableResolver<V> {
        private final VariableResolver<? extends V>[] resolvers;

        public Union(VariableResolver<? extends V>... resolvers) {
            this.resolvers = resolvers.clone();
        }

        public Union(Collection<? extends VariableResolver<? extends V>> resolvers) {
            this.resolvers = resolvers.toArray(new VariableResolver[resolvers.size()]);
        }

        public V resolve(String name) {
            for (VariableResolver<? extends V> r : resolvers) {
                V v = r.resolve(name);
                if (v != null)
                    return v;
            }
            return null;
        }
    }
}
