// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.network

import android.content.Context
import com.mesflit.trustcheck.core.security.LocalBlocklist
import com.mesflit.trustcheck.core.security.ThreatFeedIndex
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.DataOutputStream
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.LongBuffer
import java.nio.channels.FileChannel
import java.security.DigestInputStream
import java.security.MessageDigest
import java.util.zip.GZIPInputStream

/** Metadata published next to the feed by `.github/workflows/threat-feed.yml`. */
@Serializable
data class ThreatFeedMeta(
    val version: String,
    val count: Int,
    val sha256: String,
    val file: String = "feed.txt.gz",
    val sources: List<ThreatFeedSource> = emptyList(),
)

@Serializable
data class ThreatFeedSource(val name: String, val license: String, val url: String, val category: String = "phishing")

data class ThreatFeedStatus(val version: String?, val count: Int, val updatedAt: Long, val sources: String?)

/**
 * The daily threat list, built for free by GitHub Actions from openly licensed sources and
 * published as a GitHub Release asset. The app downloads it directly from GitHub — no server,
 * no API key, no cost — verifies its SHA-256 and checks links **on the device**: no URL the user
 * scans is ever sent anywhere for this check.
 */
class ThreatFeedStore(context: Context, private val http: OkHttpClient = Http.client) : LocalBlocklist {
    private val appContext = context.applicationContext
    private val file = File(appContext.filesDir, "threat-feed.bin")
    private val prefs = appContext.getSharedPreferences("threat_feed", Context.MODE_PRIVATE)
    private val lock = Mutex()
    @Volatile private var mapped: LongBuffer? = null

    fun status(): ThreatFeedStatus = ThreatFeedStatus(
        version = prefs.getString(K_VERSION, null),
        count = prefs.getInt(K_COUNT, 0),
        updatedAt = prefs.getLong(K_UPDATED, 0L),
        sources = prefs.getString(K_SOURCES, null),
    )

    // --- LocalBlocklist ---------------------------------------------------------------------

    /** Treated as unavailable when missing or older than [STALE_AFTER_MS], so stale data never yields "no known threat". */
    override suspend fun isEmpty(): Boolean {
        val s = status()
        return s.count == 0 || !file.exists() || System.currentTimeMillis() - s.updatedAt > STALE_AFTER_MS
    }

    override suspend fun match(hostAndParents: List<String>): String? = withContext(Dispatchers.IO) {
        val buf = buffer() ?: return@withContext null
        val size = buf.capacity()
        val hit = hostAndParents.firstOrNull { h ->
            val key = ThreatFeedIndex.keyOf(h)
            ThreatFeedIndex.contains(size, key) { buf.get(it) }
        }
        hit?.let { "phishing@${status().sources ?: "threat-feed"}" }
    }

    private fun buffer(): LongBuffer? {
        mapped?.let { return it }
        if (!file.exists() || file.length() < 8) return null
        return RandomAccessFile(file, "r").use { raf ->
            raf.channel.map(FileChannel.MapMode.READ_ONLY, 0, raf.length()).asLongBuffer()
        }.also { mapped = it }
    }

    // --- Sync -------------------------------------------------------------------------------

    sealed interface SyncResult {
        data class Updated(val count: Int) : SyncResult
        data object UpToDate : SyncResult
        data class Failed(val reason: String, val retryable: Boolean) : SyncResult
    }

    suspend fun sync(force: Boolean = false): SyncResult = lock.withLock {
        withContext(Dispatchers.IO) {
            try {
                val meta = fetchMeta() ?: return@withContext SyncResult.Failed("meta", retryable = true)
                if (!force && meta.version == prefs.getString(K_VERSION, null) && file.exists()) {
                    prefs.edit().putLong(K_UPDATED, System.currentTimeMillis()).apply()
                    return@withContext SyncResult.UpToDate
                }
                val keys = download(meta) ?: return@withContext SyncResult.Failed("checksum", retryable = true)
                if (keys.size < MIN_ENTRIES) return@withContext SyncResult.Failed("too_small", retryable = false)
                writeAtomically(keys)
                prefs.edit()
                    .putString(K_VERSION, meta.version)
                    .putInt(K_COUNT, keys.size)
                    .putLong(K_UPDATED, System.currentTimeMillis())
                    .putString(K_SOURCES, meta.sources.joinToString(", ") { it.name }.ifEmpty { null })
                    .apply()
                SyncResult.Updated(keys.size)
            } catch (e: IOException) {
                SyncResult.Failed(e.javaClass.simpleName, retryable = true)
            } catch (e: OutOfMemoryError) {
                SyncResult.Failed("oom", retryable = false)
            }
        }
    }

    private fun fetchMeta(): ThreatFeedMeta? {
        http.newCall(Request.Builder().url("$BASE_URL/feed.json").build()).execute().use { resp ->
            if (!resp.isSuccessful) return null
            return runCatching { Http.json.decodeFromString(ThreatFeedMeta.serializer(), resp.body?.string().orEmpty()) }.getOrNull()
        }
    }

    /** Streams, decompresses and indexes the feed while computing its SHA-256; null if the hash does not match. */
    private fun download(meta: ThreatFeedMeta): LongArray? {
        val name = meta.file.substringAfterLast('/')
        http.newCall(Request.Builder().url("$BASE_URL/$name").build()).execute().use { resp ->
            if (!resp.isSuccessful) throw IOException("http_${resp.code}")
            val digest = MessageDigest.getInstance("SHA-256")
            val body = resp.body ?: throw IOException("empty")
            val keys = DigestInputStream(body.byteStream(), digest).use { raw ->
                // Not closed here: closing the reader would close `raw` before it is drained.
                val built = ThreatFeedIndex.build(GZIPInputStream(raw).bufferedReader().lineSequence())
                val sink = ByteArray(8192)
                while (raw.read(sink) >= 0) Unit // digest must cover the whole file
                built
            }
            val actual = digest.digest().joinToString("") { "%02x".format(it) }
            return if (actual.equals(meta.sha256, ignoreCase = true)) keys else null
        }
    }

    private fun writeAtomically(keys: LongArray) {
        val tmp = File(file.path + ".tmp")
        DataOutputStream(tmp.outputStream().buffered(1 shl 16)).use { out -> keys.forEach(out::writeLong) }
        mapped = null
        if (!tmp.renameTo(file)) { file.delete(); tmp.renameTo(file) }
    }

    fun clear() {
        mapped = null
        file.delete()
        prefs.edit().clear().apply()
    }

    companion object {
        /** Public GitHub Release that the threat-feed workflow updates daily. */
        const val BASE_URL = "https://github.com/mesflit/TrustCheck/releases/download/threat-feed"
        const val STALE_AFTER_MS = 10L * 24 * 60 * 60 * 1000
        private const val MIN_ENTRIES = 100
        private const val K_VERSION = "version"
        private const val K_COUNT = "count"
        private const val K_UPDATED = "updated_at"
        private const val K_SOURCES = "sources"
    }
}
