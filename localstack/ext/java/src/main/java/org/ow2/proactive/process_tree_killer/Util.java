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
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class Util {

    /**
     * Pattern for capturing variables. Either $xyz, ${xyz} or ${a.b} but not $a.b, while ignoring "$$"
     */
    private static final Pattern VARIABLE = Pattern.compile("\\$([A-Za-z0-9_]+|\\{[A-Za-z0-9_.]+\\}|\\$)");

    /**
     * Concatenate multiple strings by inserting a separator.
     */
    public static String join(Collection<?> strings, String separator) {
        StringBuilder buf = new StringBuilder();
        boolean first = true;
        for (Object s : strings) {
            if (first)
                first = false;
            else
                buf.append(separator);
            buf.append(s);
        }
        return buf.toString();
    }

    /**
     * Replaces the occurrence of '$key' by <tt>properties.get('key')</tt>.
     *
     * <p>
     * Unlike shell, undefined variables are left as-is (this behavior is the same as Ant.)
     *
     */

    public static String replaceMacro(String s, Map<String, String> properties) {
        return replaceMacro(s, new VariableResolver.ByMap<String>(properties));
    }

    /**
     * Replaces the occurrence of '$key' by <tt>resolver.get('key')</tt>.
     *
     * <p>
     * Unlike shell, undefined variables are left as-is (this behavior is the same as Ant.)
     */
    public static String replaceMacro(String s, VariableResolver<String> resolver) {
        if (s == null) {
            return null;
        }

        int idx = 0;
        while (true) {
            Matcher m = VARIABLE.matcher(s);
            if (!m.find(idx))
                return s;

            String key = m.group().substring(1);

            // escape the dollar sign or get the key to resolve
            String value;
            if (key.charAt(0) == '$') {
                value = "$";
            } else {
                if (key.charAt(0) == '{')
                    key = key.substring(1, key.length() - 1);
                value = resolver.resolve(key);
            }

            if (value == null)
                idx = m.end(); // skip this
            else {
                s = s.substring(0, m.start()) + value + s.substring(m.end());
                idx = m.start() + value.length();
            }
        }
    }

}
