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

import java.io.File;
import java.util.Locale;


/**
 * Strategy object that absorbs the platform differences.
 *
 * <p>
 * Do not switch/case on this enum, or do a comparison, as we may add new constants.
 *
 * @author Kohsuke Kawaguchi
 */
public enum Platform {
    WINDOWS(';'),
    UNIX(':');

    /**
     * The character that separates paths in environment variables like PATH and CLASSPATH. 
     * On Windows ';' and on Unix ':'.
     *
     * @see File#pathSeparator
     */
    public final char pathSeparator;

    private Platform(char pathSeparator) {
        this.pathSeparator = pathSeparator;
    }

    public static Platform current() {
        if (File.pathSeparatorChar == ':')
            return UNIX;
        return WINDOWS;
    }

    public static boolean isDarwin() {
        // according to http://developer.apple.com/technotes/tn2002/tn2110.html
        return System.getProperty("os.name").toLowerCase(Locale.ENGLISH).startsWith("mac");
    }

    /**
     * Returns true if we run on Mac OS X >= 10.6
     */
    public static boolean isSnowLeopardOrLater() {
        try {
            return isDarwin() &&
                   new VersionNumber(System.getProperty("os.version")).compareTo(new VersionNumber("10.6")) >= 0;
        } catch (IllegalArgumentException e) {
            // failed to parse the version
            return false;
        }
    }
}
