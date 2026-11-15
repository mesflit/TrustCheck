package com.mesflit.trustcheck.core.localization

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Guards translation completeness: every shipped locale must define exactly the default
 * (English) keys with the same format placeholders. Pure JVM — reads res/ directly.
 */
class StringResourcesTest {

    private val resDir = File(System.getProperty("trustcheck.resDir") ?: "src/main/res")
    private val placeholder = Regex("%\\d\\$[sd]")

    private fun load(folder: String): Map<String, String> {
        val file = File(resDir, "$folder/strings.xml")
        assertTrue("missing ${file.path}", file.exists())
        val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file)
        val nodes = doc.getElementsByTagName("string")
        return (0 until nodes.length).associate { i ->
            val e = nodes.item(i)
            e.attributes.getNamedItem("name").nodeValue to e.textContent
        }
    }

    private val localeFolders = mapOf(
        AppLanguage.TURKISH to "values-tr",
        AppLanguage.GERMAN to "values-de",
        AppLanguage.SPANISH to "values-es",
        AppLanguage.FRENCH to "values-fr",
        AppLanguage.PORTUGUESE_BR to "values-pt-rBR",
        AppLanguage.ARABIC to "values-ar",
        AppLanguage.JAPANESE to "values-ja",
        AppLanguage.RUSSIAN to "values-ru",
    )

    @Test fun everySupportedLanguageHasAResourceFolder() {
        assertEquals(AppLanguage.supported.toSet() - AppLanguage.ENGLISH, localeFolders.keys)
    }

    @Test fun allLocalesAreCompleteAndConsistent() {
        val base = load("values") - "app_name"
        assertTrue("default strings look empty", base.size > 200)
        for ((lang, folder) in localeFolders) {
            val t = load(folder)
            assertEquals("$lang missing keys", emptySet<String>(), base.keys - t.keys)
            assertEquals("$lang extra keys", emptySet<String>(), t.keys - base.keys)
            for ((k, v) in t) {
                assertTrue("$lang:$k is empty", v.isNotBlank())
                assertEquals("$lang:$k placeholders", placeholder.findAll(base.getValue(k)).map { it.value }.sorted().toList(), placeholder.findAll(v).map { it.value }.sorted().toList())
            }
        }
    }
}
