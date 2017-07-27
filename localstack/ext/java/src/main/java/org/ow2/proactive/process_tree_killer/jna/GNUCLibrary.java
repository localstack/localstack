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
package org.ow2.proactive.process_tree_killer.jna;

import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.StringArray;
import com.sun.jna.ptr.IntByReference;


/**
 * GNU C library.
 *
 * <p>
 * Not available on all platforms (such as Linux/PPC, IBM mainframe, etc.), so the caller should recover gracefully
 * in case of {@link LinkageError}. See HUDSON-4820.
 * @author Kohsuke Kawaguchi
 */
public interface GNUCLibrary extends Library {
    int fork();

    int kill(int pid, int signum);

    int setsid();

    int umask(int mask);

    int getpid();

    int geteuid();

    int getegid();

    int getppid();

    int chdir(String dir);

    int getdtablesize();

    int execv(String path, StringArray args);

    int execvp(String file, StringArray args);

    int setenv(String name, String value, int replace);

    int unsetenv(String name);

    void perror(String msg);

    String strerror(int errno);

    int fcntl(int fd, int command);

    int fcntl(int fd, int command, int flags);

    // obtained from Linux. Needs to be checked if these values are portable.
    int F_GETFD = 1;

    int F_SETFD = 2;

    int FD_CLOEXEC = 1;

    int chown(String fileName, int uid, int gid);

    int chmod(String fileName, int i);

    int dup(int old);

    int dup2(int old, int _new);

    int close(int fd);

    // see http://www.gnu.org/s/libc/manual/html_node/Renaming-Files.html
    int rename(String oldname, String newname);

    // this is listed in http://developer.apple.com/DOCUMENTATION/Darwin/Reference/ManPages/man3/sysctlbyname.3.html
    // but not in http://www.gnu.org/software/libc/manual/html_node/System-Parameters.html#index-sysctl-3493
    // perhaps it is only supported on BSD?
    int sysctlbyname(String name, Pointer oldp, IntByReference oldlenp, Pointer newp, IntByReference newlen);

    int sysctl(int[] mib, int nameLen, Pointer oldp, IntByReference oldlenp, Pointer newp, IntByReference newlen);

    int sysctlnametomib(String name, Pointer mibp, IntByReference size);

    /**
     * Creates a symlink.
     *
     * See http://linux.die.net/man/3/symlink
     */
    int symlink(String oldname, String newname);

    /**
     * Read a symlink. The name will be copied into the specified memory, and returns the number of
     * bytes copied. The string is not null-terminated.
     *
     * @return
     *      if the return value equals size, the caller needs to retry with a bigger buffer.
     *      If -1, error.
     */
    int readlink(String filename, Memory buffer, NativeLong size);

    GNUCLibrary LIBC = (GNUCLibrary) Native.loadLibrary("c", GNUCLibrary.class);
}
