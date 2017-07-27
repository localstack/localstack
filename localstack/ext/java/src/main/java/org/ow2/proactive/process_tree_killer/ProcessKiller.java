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

import java.io.IOException;
import java.io.Serializable;


/**
 * Extension point that defines more elaborate way of killing processes, such as
 * sudo or pfexec, for {@link ProcessTree}.
 *
 * <h2>Lifecycle</h2>
 * <p>
 * Each implementation of {@link ProcessKiller} is instantiated once on the master.
 * Whenever a process needs to be killed, those implementations are serialized and sent over
 * to the appropriate slave, then the {@link #kill(ProcessTree.OSProcess)} method is invoked
 * to attempt to kill the process.
 *
 * <p>
 * One of the consequences of this design is that the implementation should be stateless
 * and concurrent-safe. That is, the {@link #kill(ProcessTree.OSProcess)} method can be invoked by multiple threads
 * concurrently on the single instance.
 *
 * <p>
 * Another consequence of this design is that if your {@link ProcessKiller} requires configuration,
 * it needs to be serializable, and configuration needs to be updated atomically, as another
 * thread may be calling into {@link #kill(ProcessTree.OSProcess)} just when you are updating your configuration.
 *
 * @author jpederzolli
 * @author Kohsuke Kawaguchi
 * @since 1.362
 */
public abstract class ProcessKiller implements Serializable {

    /**
     * Attempts to kill the given process.
     *
     * @param process process to be killed. Always a {@linkplain ProcessTree.Local local process}.
     * @return
     *      true if the killing was successful, and Hudson won't try to use other {@link ProcessKiller}
     *      implementations to kill the process. false if the killing failed or is unattempted, and Hudson will continue
     *      to use the rest of the {@link ProcessKiller} implementations to try to kill the process.
     * @throws IOException
     *      The caller will log this exception and otherwise treat as if the method returned false, and moves on
     *      to the next killer.
     * @throws InterruptedException
     *      if the callee performs a time consuming operation and if the thread is canceled, do not catch
     *      {@link InterruptedException} and just let it thrown from the method.
     */
    public abstract boolean kill(ProcessTree.OSProcess process) throws IOException, InterruptedException;

    private static final long serialVersionUID = 1L;
}
