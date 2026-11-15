package com.mesflit.trustcheck.core.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DomainUtilsTest {
    @Test fun registrableDomain() {
        assertEquals("example.com", DomainUtils.registrableDomain("a.b.example.com"))
        assertEquals("bbc.co.uk", DomainUtils.registrableDomain("www.bbc.co.uk"))
        assertEquals("evil.com.tr", DomainUtils.registrableDomain("paypal.com.evil.com.tr"))
        assertEquals("attacker.github.io", DomainUtils.registrableDomain("x.attacker.github.io"))
        assertEquals("1.2.3.4", DomainUtils.registrableDomain("1.2.3.4"))
    }

    @Test fun subdomainLabels() {
        assertEquals(listOf("login", "paypal", "com"), DomainUtils.subdomainLabels("login.paypal.com.verify.xyz"))
        assertEquals(emptyList<String>(), DomainUtils.subdomainLabels("example.com"))
    }

    @Test fun ipDetection() {
        assertTrue(DomainUtils.isIpv4("192.168.1.1"))
        assertFalse(DomainUtils.isIpv4("256.1.1.1"))
        assertTrue(DomainUtils.isObfuscatedIp("3232235777"))
        assertTrue(DomainUtils.isObfuscatedIp("0x7f000001"))
        assertTrue(DomainUtils.isObfuscatedIp("0177.0.0.1"))
        assertFalse(DomainUtils.isObfuscatedIp("8.8.8.8"))
        assertFalse(DomainUtils.isObfuscatedIp("example.com"))
        assertTrue(DomainUtils.isPrivateOrLocal("10.0.0.5"))
        assertTrue(DomainUtils.isPrivateOrLocal("172.20.1.1"))
        assertFalse(DomainUtils.isPrivateOrLocal("172.32.1.1"))
    }

    @Test fun hostAndParents() {
        assertEquals(listOf("a.b.example.com", "b.example.com", "example.com"), DomainUtils.hostAndParents("a.b.example.com"))
    }
}
