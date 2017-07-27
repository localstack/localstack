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
import java.util.List;
import java.util.NoSuchElementException;
import java.util.StringTokenizer;


/* ------------------------------------------------------------ */

/** StringTokenizer with Quoting support.
 *
 * This class is a copy of the java.util.StringTokenizer API and
 * the behaviour is the same, except that single and doulbe quoted
 * string values are recognized.
 * Delimiters within quotes are not considered delimiters.
 * Quotes can be escaped with '\'.
 *
 * @see StringTokenizer
 * @author Greg Wilkins (gregw)
 */
public class QuotedStringTokenizer extends StringTokenizer {
    private final static String __delim = " \t\n\r";

    private String _string;

    private String _delim = __delim;

    private boolean _returnQuotes = false;

    private boolean _returnDelimiters = false;

    private StringBuilder _token;

    private boolean _hasToken = false;

    private int _i = 0;

    private int _lastStart = 0;

    private boolean _double = true;

    private boolean _single = true;

    public static String[] tokenize(String str) {
        return new QuotedStringTokenizer(str).toArray();
    }

    public static String[] tokenize(String str, String delimiters) {
        return new QuotedStringTokenizer(str, delimiters).toArray();
    }

    /* ------------------------------------------------------------ */
    /**
     *
     * @param str
     *      String to tokenize.
     * @param delim
     *      List of delimiter characters as string. Can be null, to default to ' \t\n\r'
     * @param returnDelimiters
     *      If true, {@link #nextToken()} will include the delimiters, not just tokenized
     *      tokens.
     * @param returnQuotes
     *      If true, {@link #nextToken()} will include the quotation characters when they are present.
     */
    public QuotedStringTokenizer(String str, String delim, boolean returnDelimiters, boolean returnQuotes) {
        super("");
        _string = str;
        if (delim != null)
            _delim = delim;
        _returnDelimiters = returnDelimiters;
        _returnQuotes = returnQuotes;

        if (_delim.indexOf('\'') >= 0 || _delim.indexOf('"') >= 0)
            throw new Error("Can't use quotes as delimiters: " + _delim);

        _token = new StringBuilder(_string.length() > 1024 ? 512 : _string.length() / 2);
    }

    /* ------------------------------------------------------------ */
    public QuotedStringTokenizer(String str, String delim, boolean returnDelimiters) {
        this(str, delim, returnDelimiters, false);
    }

    /* ------------------------------------------------------------ */
    public QuotedStringTokenizer(String str, String delim) {
        this(str, delim, false, false);
    }

    /* ------------------------------------------------------------ */
    public QuotedStringTokenizer(String str) {
        this(str, null, false, false);
    }

    public String[] toArray() {
        List<String> r = new ArrayList<String>();
        while (hasMoreTokens())
            r.add(nextToken());
        return r.toArray(new String[r.size()]);
    }

    /* ------------------------------------------------------------ */
    @Override
    public boolean hasMoreTokens() {
        // Already found a token
        if (_hasToken)
            return true;

        _lastStart = _i;

        int state = 0;
        boolean escape = false;
        while (_i < _string.length()) {
            char c = _string.charAt(_i++);

            switch (state) {
                case 0: // Start
                    if (_delim.indexOf(c) >= 0) {
                        if (_returnDelimiters) {
                            _token.append(c);
                            return _hasToken = true;
                        }
                    } else if (c == '\'' && _single) {
                        if (_returnQuotes)
                            _token.append(c);
                        state = 2;
                    } else if (c == '\"' && _double) {
                        if (_returnQuotes)
                            _token.append(c);
                        state = 3;
                    } else {
                        _token.append(c);
                        _hasToken = true;
                        state = 1;
                    }
                    continue;

                case 1: // Token
                    _hasToken = true;
                    if (escape) {
                        escape = false;
                        if (ESCAPABLE_CHARS.indexOf(c) < 0)
                            _token.append('\\');
                        _token.append(c);
                    } else if (_delim.indexOf(c) >= 0) {
                        if (_returnDelimiters)
                            _i--;
                        return _hasToken;
                    } else if (c == '\'' && _single) {
                        if (_returnQuotes)
                            _token.append(c);
                        state = 2;
                    } else if (c == '\"' && _double) {
                        if (_returnQuotes)
                            _token.append(c);
                        state = 3;
                    } else if (c == '\\') {
                        escape = true;
                    } else
                        _token.append(c);
                    continue;

                case 2: // Single Quote
                    _hasToken = true;
                    if (escape) {
                        escape = false;
                        if (ESCAPABLE_CHARS.indexOf(c) < 0)
                            _token.append('\\');
                        _token.append(c);
                    } else if (c == '\'') {
                        if (_returnQuotes)
                            _token.append(c);
                        state = 1;
                    } else if (c == '\\') {
                        if (_returnQuotes)
                            _token.append(c);
                        escape = true;
                    } else
                        _token.append(c);
                    continue;

                case 3: // Double Quote
                    _hasToken = true;
                    if (escape) {
                        escape = false;
                        if (ESCAPABLE_CHARS.indexOf(c) < 0)
                            _token.append('\\');
                        _token.append(c);
                    } else if (c == '\"') {
                        if (_returnQuotes)
                            _token.append(c);
                        state = 1;
                    } else if (c == '\\') {
                        if (_returnQuotes)
                            _token.append(c);
                        escape = true;
                    } else
                        _token.append(c);
                    continue;
            }
        }

        return _hasToken;
    }

    /* ------------------------------------------------------------ */
    @Override
    public String nextToken() throws NoSuchElementException {
        if (!hasMoreTokens() || _token == null)
            throw new NoSuchElementException();
        String t = _token.toString();
        _token.setLength(0);
        _hasToken = false;
        return t;
    }

    /* ------------------------------------------------------------ */
    @Override
    public String nextToken(String delim) throws NoSuchElementException {
        _delim = delim;
        _i = _lastStart;
        _token.setLength(0);
        _hasToken = false;
        return nextToken();
    }

    /* ------------------------------------------------------------ */
    @Override
    public boolean hasMoreElements() {
        return hasMoreTokens();
    }

    /* ------------------------------------------------------------ */
    @Override
    public Object nextElement() throws NoSuchElementException {
        return nextToken();
    }

    /* ------------------------------------------------------------ */
    /** Not implemented.
     */
    @Override
    public int countTokens() {
        return -1;
    }

    /* ------------------------------------------------------------ */
    /** Quote a string.
     * The string is quoted only if quoting is required due to
     * embeded delimiters, quote characters or the
     * empty string.
     * @param s The string to quote.
     * @return quoted string
     */
    public static String quote(String s, String delim) {
        if (s == null)
            return null;
        if (s.length() == 0)
            return "\"\"";

        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' || c == '"' || c == '\'' || Character.isWhitespace(c) || delim.indexOf(c) >= 0) {
                StringBuffer b = new StringBuffer(s.length() + 8);
                quote(b, s);
                return b.toString();
            }
        }

        return s;
    }

    /* ------------------------------------------------------------ */
    /** Quote a string.
     * The string is quoted only if quoting is required due to
     * embeded delimiters, quote characters or the
     * empty string.
     * @param s The string to quote.
     * @return quoted string
     */
    public static String quote(String s) {
        if (s == null)
            return null;
        if (s.length() == 0)
            return "\"\"";

        StringBuffer b = new StringBuffer(s.length() + 8);
        quote(b, s);
        return b.toString();

    }

    /* ------------------------------------------------------------ */
    /** Quote a string into a StringBuffer.
     * The characters ", \, \n, \r, \t, \f and \b are escaped
     * @param buf The StringBuffer
     * @param s The String to quote.
     */
    public static void quote(StringBuffer buf, String s) {
        synchronized (buf) {
            buf.append('"');
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '"':
                        buf.append("\\\"");
                        continue;
                    case '\\':
                        buf.append("\\\\");
                        continue;
                    case '\n':
                        buf.append("\\n");
                        continue;
                    case '\r':
                        buf.append("\\r");
                        continue;
                    case '\t':
                        buf.append("\\t");
                        continue;
                    case '\f':
                        buf.append("\\f");
                        continue;
                    case '\b':
                        buf.append("\\b");
                        continue;

                    default:
                        buf.append(c);
                        continue;
                }
            }
            buf.append('"');
        }
    }

    /* ------------------------------------------------------------ */
    /** Unquote a string.
     * @param s The string to unquote.
     * @return quoted string
     */
    public static String unquote(String s) {
        if (s == null)
            return null;
        if (s.length() < 2)
            return s;

        char first = s.charAt(0);
        char last = s.charAt(s.length() - 1);
        if (first != last || (first != '"' && first != '\''))
            return s;

        StringBuilder b = new StringBuilder(s.length() - 2);
        boolean escape = false;
        for (int i = 1; i < s.length() - 1; i++) {
            char c = s.charAt(i);

            if (escape) {
                escape = false;
                switch (c) {
                    case 'n':
                        b.append('\n');
                        break;
                    case 'r':
                        b.append('\r');
                        break;
                    case 't':
                        b.append('\t');
                        break;
                    case 'f':
                        b.append('\f');
                        break;
                    case 'b':
                        b.append('\b');
                        break;
                    case 'u':
                        b.append((char) ((convertHexDigit((byte) s.charAt(i++)) << 24) +
                                         (convertHexDigit((byte) s.charAt(i++)) << 16) +
                                         (convertHexDigit((byte) s.charAt(i++)) << 8) +
                                         (convertHexDigit((byte) s.charAt(i++)))));
                        break;
                    default:
                        b.append(c);
                }
            } else if (c == '\\') {
                escape = true;
                continue;
            } else
                b.append(c);
        }

        return b.toString();
    }

    /* ------------------------------------------------------------ */
    /**
     * @return handle double quotes if true
     */
    public boolean getDouble() {
        return _double;
    }

    /* ------------------------------------------------------------ */
    /**
     * @param d handle double quotes if true
     */
    public void setDouble(boolean d) {
        _double = d;
    }

    /* ------------------------------------------------------------ */
    /**
     * @return handle single quotes if true
     */
    public boolean getSingle() {
        return _single;
    }

    /* ------------------------------------------------------------ */
    /**
     * @param single handle single quotes if true
     */
    public void setSingle(boolean single) {
        _single = single;
    }

    /**
     * @param b An ASCII encoded character 0-9 a-f A-F
     * @return The byte value of the character 0-16.
     */
    public static byte convertHexDigit(byte b) {
        if ((b >= '0') && (b <= '9'))
            return (byte) (b - '0');
        if ((b >= 'a') && (b <= 'f'))
            return (byte) (b - 'a' + 10);
        if ((b >= 'A') && (b <= 'F'))
            return (byte) (b - 'A' + 10);
        return 0;
    }

    /**
     * Characters that can be escaped with \.
     *
     * Others, like, say, \W will be left alone instead of becoming just W.
     * This is important to keep Hudson behave on Windows, which uses '\' as
     * the directory separator. 
     */
    private static final String ESCAPABLE_CHARS = "\\\"' ";
}
