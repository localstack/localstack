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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Stack;


/**
 * Traverses a directed graph and if it contains any cycle, throw an exception.
 *
 * @author Kohsuke Kawaguchi
 */
@SuppressWarnings("all")
public abstract class CyclicGraphDetector<N> {
    private final Set<N> visited = new HashSet<N>();

    private final Set<N> visiting = new HashSet<N>();

    private final Stack<N> path = new Stack<N>();

    private final List<N> topologicalOrder = new ArrayList<N>();

    public void run(Iterable<? extends N> allNodes) throws CycleDetectedException {
        for (N n : allNodes) {
            visit(n);
        }
    }

    /**
     * Returns all the nodes in the topologically sorted order.
     * That is, if there's an edge a->b, b always come earlier than a.
     */
    public List<N> getSorted() {
        return topologicalOrder;
    }

    /**
     * List up edges from the given node (by listing nodes that those edges point to.)
     *
     * @return
     *      Never null.
     */
    protected abstract Iterable<? extends N> getEdges(N n);

    private void visit(N p) throws CycleDetectedException {
        if (!visited.add(p))
            return;

        visiting.add(p);
        path.push(p);
        for (N q : getEdges(p)) {
            if (q == null)
                continue; // ignore unresolved references
            if (visiting.contains(q))
                detectedCycle(q);
            visit(q);
        }
        visiting.remove(p);
        path.pop();
        topologicalOrder.add(p);
    }

    private void detectedCycle(N q) throws CycleDetectedException {
        int i = path.indexOf(q);
        path.push(q);
        reactOnCycle(q, path.subList(i, path.size()));
    }

    /**
     * React on detected cycles - default implementation throws an exception.
     * @param q
     * @param cycle
     * @throws CycleDetectedException
     */
    protected void reactOnCycle(N q, List<N> cycle) throws CycleDetectedException {
        throw new CycleDetectedException(cycle);
    }

	public static final class CycleDetectedException extends Exception {
        public final List cycle;

        public CycleDetectedException(List cycle) {
            super("Cycle detected: " + Util.join(cycle, " -> "));
            this.cycle = cycle;
        }
    }
}
