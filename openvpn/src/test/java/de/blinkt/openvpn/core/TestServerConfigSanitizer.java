/*
 * Copyright (c) 2026 Windscribe Limited.
 */

package de.blinkt.openvpn.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * The server config is attacker controlled whenever the ServerConfigs response is, so these cases
 * are the security boundary rather than ordinary parsing coverage.
 *
 * The spellings below are not exotic: the engine's parse_line() unwraps quotes and backslashes on
 * the option name and bypass_doubledash() strips a leading double dash, so every one of them
 * reaches add_option() as plain "up". A filter that splits on whitespace passes all but the first.
 */
public class TestServerConfigSanitizer {

    private static final String CMD = " \"/system/bin/sh -c 'touch /data/data/PWNED'\"";

    private static void assertRemoved(String line) {
        ServerConfigSanitizer.Result r = ServerConfigSanitizer.sanitize(line + "\n");
        assertFalse("directive survived sanitising: " + line, r.config.contains("PWNED"));
        assertFalse("nothing was reported as dropped for: " + line, r.dropped.isEmpty());
    }

    private static void assertKept(String line) {
        ServerConfigSanitizer.Result r = ServerConfigSanitizer.sanitize(line + "\n");
        assertTrue("legitimate directive was dropped: " + line, r.config.contains(line.trim()));
        assertTrue("unexpected drops for: " + line, r.dropped.isEmpty());
    }

    @Test
    public void removesEverySpellingOfUp() {
        assertRemoved("up" + CMD);
        assertRemoved("--up" + CMD);
        assertRemoved("\"up\"" + CMD);
        assertRemoved("'up'" + CMD);
        assertRemoved("\\u\\p" + CMD);
        assertRemoved("   \t up" + CMD);
        assertRemoved("up\t\"touch /data/data/PWNED\"");
    }

    @Test
    public void removesTheRestOfTheCommandExecutingFamily() {
        assertRemoved("down" + CMD);
        assertRemoved("route-up" + CMD);
        assertRemoved("route-pre-down" + CMD);
        assertRemoved("ipchange" + CMD);
        assertRemoved("tls-verify" + CMD);
        assertRemoved("client-connect" + CMD);
        assertRemoved("client-disconnect" + CMD);
        assertRemoved("learn-address" + CMD);
        assertRemoved("auth-user-pass-verify" + CMD);
        assertRemoved("script-security 2 # PWNED");
        assertRemoved("plugin /data/local/tmp/PWNED.so");
    }

    @Test
    public void refusesToLetTheServerNameLocalFiles() {
        // ca/cert/key are accepted only as inline blocks, never as a path.
        assertRemoved("ca /data/data/PWNED");
        assertRemoved("cert /data/data/PWNED");
        assertRemoved("key /data/data/PWNED");
        assertRemoved("tmp-dir /data/data/PWNED");
    }

    @Test
    public void refusesToLetTheServerPickTheEndpoint() {
        // getConfigFile() injects its own remote and previously only appended, so a server-supplied
        // remote survived beside it. Multiple remotes are a connection list tried in order, so one
        // placed above the dev line was tried first.
        ServerConfigSanitizer.Result r =
                ServerConfigSanitizer.sanitize("remote 10.9.9.9 443 udp\nclient\ndev tun\n");
        assertFalse(r.config.contains("10.9.9.9"));
        assertTrue(r.config.contains("dev tun"));
        assertTrue(r.dropped.contains("remote"));
    }

    @Test
    public void discardsTheBodyOfARejectedInlineBlock() {
        // If only the tag were dropped, the body would be read back as directives.
        ServerConfigSanitizer.Result r =
                ServerConfigSanitizer.sanitize("client\n<up>\nPWNED\n</up>\nverb 2\n");
        assertFalse(r.config.contains("PWNED"));
        assertTrue(r.config.contains("client"));
        assertTrue(r.config.contains("verb 2"));
        assertEquals(1, r.dropped.size());
    }

    @Test
    public void closingTagMatchesByPrefixLikeTheEngine() {
        // read_inline_file() prefix-matches after left-trimming, so a suffix still closes.
        ServerConfigSanitizer.Result r =
                ServerConfigSanitizer.sanitize("<up>\nPWNED\n  </up>trailing\nverb 2\n");
        assertFalse(r.config.contains("PWNED"));
        assertTrue(r.config.contains("verb 2"));
    }

    @Test
    public void removesOptionsThatLoadNativeCode() {
        // None of these are gated by script-security, so the argv backstop does not cover them.
        assertRemoved("pkcs11-providers /data/local/tmp/PWNED.so");
        assertRemoved("providers /data/local/tmp/PWNED.so");
        assertRemoved("engine PWNED");
    }

    @Test
    public void removesTheDnsUpdownHook() {
        // Added in OpenVPN 2.6 and easy to miss by hand: it reaches set_user_script() like --up.
        assertRemoved("dns-updown" + CMD);
    }

    @Test
    public void removesTheManagementFamily() {
        // The app writes its own management block and talks to it for credentials.
        assertRemoved("management /data/data/PWNED unix");
        assertRemoved("management-external-key PWNED");
        assertRemoved("management-up-down PWNED");
    }

    @Test
    public void refusesAuthUserPassOnlyWhenItNamesAFile() {
        // Bare form is required: it makes the engine ask for credentials over management.
        assertKept("auth-user-pass");
        assertRemoved("auth-user-pass /data/data/PWNED");
    }

    @Test
    public void letsUnknownInertDirectivesThrough() {
        // The point of the denylist: the backend can add an option without a client release.
        assertKept("mssfix 1300");
        assertKept("some-future-option 5");
    }

    @Test
    public void keepsARealServerConfig() {
        assertKept("client");
        assertKept("dev tun");
        assertKept("key-direction 1");
        assertKept("remote-cert-tls server");
        assertKept("persist-tun");
        assertKept("nobind");
        assertKept("auth-user-pass");
        assertKept("verb 2");
        // Anti-censorship tweaks appended by VPNProfileCreator.
        assertKept("udp-stuffing");
        assertKept("tcp-split-reset");
    }

    @Test
    public void passesInlineCertificateMaterialThrough() {
        String cfg = "<ca>\n-----BEGIN CERTIFICATE-----\nMIIBcert\n-----END CERTIFICATE-----\n</ca>\n"
                + "<tls-auth>\n-----BEGIN OpenVPN Static key V1-----\nabc\n"
                + "-----END OpenVPN Static key V1-----\n</tls-auth>\nverb 2\n";
        ServerConfigSanitizer.Result r = ServerConfigSanitizer.sanitize(cfg);
        assertTrue(r.config.contains("MIIBcert"));
        assertTrue(r.config.contains("OpenVPN Static key V1"));
        assertTrue(r.config.contains("verb 2"));
        assertTrue(r.dropped.isEmpty());
    }

    @Test
    public void handlesCrlfConfigs() {
        ServerConfigSanitizer.Result r = ServerConfigSanitizer.sanitize("client\r\nup" + CMD + "\r\n");
        assertFalse(r.config.contains("PWNED"));
        assertTrue(r.config.contains("client"));
    }

    @Test
    public void tokeniserMatchesTheEngine() {
        assertEquals("up", ServerConfigSanitizer.firstToken("up \"cmd\""));
        assertEquals("up", ServerConfigSanitizer.firstToken("\"up\" cmd"));
        assertEquals("up", ServerConfigSanitizer.firstToken("'up' cmd"));
        assertEquals("client", ServerConfigSanitizer.firstToken("  client  "));
        assertEquals(null, ServerConfigSanitizer.firstToken("# comment"));
        assertEquals(null, ServerConfigSanitizer.firstToken("; comment"));
        assertEquals(null, ServerConfigSanitizer.firstToken("   "));
    }
}
