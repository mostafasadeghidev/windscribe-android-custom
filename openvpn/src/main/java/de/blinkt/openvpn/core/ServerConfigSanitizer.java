/*
 * Copyright (c) 2026 Windscribe Limited.
 */

package de.blinkt.openvpn.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Filters an API-supplied OpenVPN config before it is written to disk.
 *
 * The config is attacker controlled the moment anyone can tamper with the ServerConfigs response,
 * and the bundled engine is built with HAVE_FORK/HAVE_EXECVE, so directives like up/down/plugin
 * run commands as our own uid. Directives on DENIED are removed and reported; everything else
 * passes through.
 *
 * This is a denylist rather than an allowlist, chosen so the backend can introduce a new inert
 * directive without it being silently dropped by every already-shipped client. The trade is that
 * it fails open: a dangerous directive missing from DENIED gets through. What makes that
 * acceptable here is that the engine is vendored in this repo, so the set of options it
 * understands is fixed at build time and DENIED is derived from its options.c rather than guessed.
 * Re-derive it when the vendored OpenVPN is bumped.
 *
 * Scope, so the next reader does not assume more: this keeps a tampered config off the device, not
 * out of the traffic path. The endpoint the app injects comes from the ServerList
 * response, and <ca>/<tls-auth> still arrive from the API, so anyone able to tamper with those can
 * still land a user on a server of their choosing. Closing that needs signed payloads or a pinned
 * node CA, not a bigger allowlist. Traffic steering is knowingly out of scope here.
 *
 * Tokenisation deliberately mirrors the engine's own parse_line(), bypass_doubledash() and
 * check_inline_file(), because what we match has to be what the engine acts on. Quoting, backslash
 * escapes and a leading double dash all reach add_option() as a bare directive name, so the quoted,
 * single-quoted, backslash-escaped and double-dashed spellings of "up" are one option to the engine
 * and have to be one option to us.
 */
public final class ServerConfigSanitizer {

    /**
     * Directives the server may never send, as a directive or as an inline tag.
     *
     * Enumerated from the vendored engine's own options.c rather than written from memory, because
     * a denylist is only as good as its completeness. Re-derive this list whenever the vendored
     * OpenVPN is bumped: that is the one moment the set of options the engine understands can
     * change, and it is the review point this design depends on.
     *
     * Everything not named here passes through, so the backend can start sending a new inert
     * directive without waiting for clients to catch up.
     */
    private static final Set<String> DENIED = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList(
                    // Command execution. Every option that reaches set_user_script() in options.c.
                    "up", "down", "route-up", "route-pre-down", "ipchange", "tls-verify",
                    "auth-user-pass-verify", "client-connect", "client-crresponse",
                    "client-disconnect", "learn-address", "dns-updown", "tls-crypt-v2-verify",
                    // Loads native code. None of these are gated by script-security.
                    "plugin", "providers", "engine", "pkcs11-providers",
                    // Gates the above. Also set on the command line as a backstop.
                    "script-security",
                    // Privilege and process state.
                    "user", "group", "daemon", "chroot", "cd", "setcon", "inetd", "writepid",
                    // Reads or writes local files by path.
                    "tmp-dir", "log", "log-append", "status", "client-config-dir", "askpass",
                    "capath", "config", "replay-persist", "ifconfig-pool-persist",
                    // The endpoint is ours. getConfigFile() injects its own remote after the dev
                    // line but only ever appended, and multiple remotes form a connection list
                    // tried in order, so one placed above the dev line was tried first.
                    "remote", "remote-random", "proto", "port",
                    "http-proxy", "http-proxy-option", "http-proxy-user-pass", "socks-proxy",
                    // The management channel is ours; the app writes its own block.
                    "management", "management-client", "management-client-auth",
                    "management-client-group", "management-client-user", "management-external-cert",
                    "management-external-key", "management-forget-disconnect", "management-hold",
                    "management-log-cache", "management-query-passwords", "management-query-proxy",
                    "management-query-remote", "management-signal", "management-up-down"
            )));

    /**
     * Key material: refused as a directive, allowed as an inline block.
     *
     * "ca /data/data/..." would point the engine at a local file, while the inline form carries
     * its own bytes and names nothing on disk. The real config uses the inline form.
     */
    private static final Set<String> DENIED_AS_PATH = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList(
                    "ca", "cert", "key", "dh", "pkcs12", "crl-verify", "extra-certs", "secret",
                    "tls-auth", "tls-crypt", "tls-crypt-v2"
            )));

    /** Fine bare, refused with an argument, which would name a file to read credentials from. */
    private static final Set<String> DENIED_WITH_ARGUMENT = Collections.unmodifiableSet(
            new HashSet<>(Collections.singletonList("auth-user-pass")));

    private ServerConfigSanitizer() {
    }

    public static final class Result {
        public final String config;
        /** Directive names that were removed, for logging. Never contains argument values. */
        public final List<String> dropped;

        Result(String config, List<String> dropped) {
            this.config = config;
            this.dropped = Collections.unmodifiableList(dropped);
        }
    }

    public static Result sanitize(String rawConfig) {
        List<String> kept = new ArrayList<>();
        List<String> dropped = new ArrayList<>();

        // Split on any line ending. The server config is not obliged to use the platform's, and
        // splitting on line.separator alone leaves a stray CR on every token of a CRLF config.
        String[] lines = rawConfig.split("\r?\n", -1);

        String copyingTag = null;   // inside an allowed inline block
        String skippingTag = null;  // inside a rejected inline block

        for (String line : lines) {
            if (skippingTag != null) {
                if (isCloseTag(line, skippingTag)) {
                    skippingTag = null;
                }
                continue;
            }
            if (copyingTag != null) {
                kept.add(line);
                if (isCloseTag(line, copyingTag)) {
                    copyingTag = null;
                }
                continue;
            }

            String token = firstToken(line);
            if (token == null) {
                kept.add(line);     // blank or comment
                continue;
            }
            token = bypassDoubleDash(token);

            String tag = inlineTag(line);
            if (tag != null) {
                // An inline tag is an option name: check_inline_file() turns <up>body</up> into
                // option "up" with the body as its argument, so a block is as dangerous as a line.
                if (DENIED.contains(tag)) {
                    dropped.add("<" + tag + ">");
                    skippingTag = tag;  // discard the body too, or it is read as directives
                } else {
                    kept.add(line);
                    copyingTag = tag;
                }
                continue;
            }

            boolean refuse = DENIED.contains(token)
                    || DENIED_AS_PATH.contains(token)
                    || (DENIED_WITH_ARGUMENT.contains(token) && hasArgument(line));
            if (refuse) {
                dropped.add(token);
            } else {
                kept.add(line);
            }
        }

        StringBuilder sb = new StringBuilder();
        for (String l : kept) {
            sb.append(l).append("\n");
        }
        return new Result(sb.toString(), dropped);
    }

    /**
     * Returns the inline tag name if the line is an inline open tag, else null.
     *
     * Stricter than check_inline_file(), which accepts any single parameter wrapped in angle
     * brackets. Anything that does not match the plain tag form falls through to the directive
     * allowlist and is dropped there, so the stricter test only ever fails closed.
     */
    private static String inlineTag(String line) {
        String t = line.trim();
        if (t.length() < 3 || t.charAt(0) != '<' || t.charAt(t.length() - 1) != '>') {
            return null;
        }
        String name = t.substring(1, t.length() - 1);
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok) {
                return null;
            }
        }
        return name.isEmpty() ? null : name;
    }

    /** Mirrors read_inline_file(): left-trim, then prefix match, so a trailing suffix still closes. */
    private static boolean isCloseTag(String line, String tag) {
        int i = 0;
        while (i < line.length() && isSpaceChar(line.charAt(i))) {
            i++;
        }
        return line.startsWith("</" + tag + ">", i);
    }

    /** Mirrors bypass_doubledash(). */
    private static String bypassDoubleDash(String p) {
        return (p.length() >= 3 && p.startsWith("--")) ? p.substring(2) : p;
    }

    /** The engine's isspace() set. Kept to ASCII so the token boundary cannot drift from the C. */
    private static boolean isSpaceChar(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == 0x0B || c == '\f' || c == '\r';
    }

    /**
     * Extracts the first parameter of a line exactly as parse_line() would, and returns null when
     * the line yields no parameter. Faithful port: same states, same backslash handling, same
     * treatment of the terminating NUL as whitespace.
     */
    static String firstToken(String line) {
        List<String> t = parseTokens(line, 1);
        return t.isEmpty() ? null : t.get(0);
    }

    /** True if the line carries a parameter after the directive name. */
    private static boolean hasArgument(String line) {
        return parseTokens(line, 2).size() > 1;
    }

    private static List<String> parseTokens(String line, int limit) {
        final int INITIAL = 0, QUOTED = 1, UNQUOTED = 2, DONE = 3, SQUOTED = 4;

        List<String> tokens = new ArrayList<>();
        int state = INITIAL;
        boolean backslash = false;
        StringBuilder parm = new StringBuilder();

        int i = 0;
        while (true) {
            char in = i < line.length() ? line.charAt(i) : '\0';
            char out = 0;

            if (!backslash && in == '\\' && state != SQUOTED) {
                backslash = true;
            } else {
                if (state == INITIAL) {
                    if (in != '\0' && !isSpaceChar(in)) {
                        if (in == ';' || in == '#') {
                            break;      // comment: the rest of the line is not parsed
                        }
                        if (!backslash && in == '"') {
                            state = QUOTED;
                        } else if (!backslash && in == '\'') {
                            state = SQUOTED;
                        } else {
                            out = in;
                            state = UNQUOTED;
                        }
                    }
                } else if (state == UNQUOTED) {
                    if (!backslash && (in == '\0' || isSpaceChar(in))) {
                        state = DONE;
                    } else {
                        out = in;
                    }
                } else if (state == QUOTED) {
                    if (!backslash && in == '"') {
                        state = DONE;
                    } else {
                        out = in;
                    }
                } else if (state == SQUOTED) {
                    if (in == '\'') {
                        state = DONE;
                    } else {
                        out = in;
                    }
                }

                if (state == DONE) {
                    tokens.add(parm.toString());
                    if (tokens.size() >= limit) {
                        return tokens;
                    }
                    parm.setLength(0);
                    state = INITIAL;
                }
                backslash = false;
            }

            if (out != 0) {
                parm.append(out);
            }
            if (i >= line.length()) {
                break;
            }
            i++;
        }
        return tokens;
    }
}
