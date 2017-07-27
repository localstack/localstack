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

import java.io.Serializable;
import java.util.Comparator;


/**
 * Case-insensitive string comparator.
 *
 * @author Kohsuke Kawaguchi
 */
public final class CaseInsensitiveComparator implements Comparator<String>, Serializable {
    public static final Comparator<String> INSTANCE = new CaseInsensitiveComparator();

    private CaseInsensitiveComparator() {
    }

    public int compare(String lhs, String rhs) {
        return lhs.compareToIgnoreCase(rhs);
    }

    private static final long serialVersionUID = 1L;
}
