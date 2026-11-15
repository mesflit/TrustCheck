package com.mesflit.trustcheck.data

import android.app.Application
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.mesflit.trustcheck.core.database.TrustCheckDatabase
import com.mesflit.trustcheck.core.security.RiskClassification
import com.mesflit.trustcheck.core.security.UrlAnalysisEngine
import com.mesflit.trustcheck.domain.ScanOrigin
import com.mesflit.trustcheck.domain.TargetType
import com.mesflit.trustcheck.domain.UserAction
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class ScanRepositoryTest {
    private lateinit var db: TrustCheckDatabase
    private lateinit var repo: ScanRepositoryImpl
    private val engine = UrlAnalysisEngine(clock = { 1_000L })

    @Before fun setUp() {
        db = Room.inMemoryDatabaseBuilder(ApplicationProvider.getApplicationContext(), TrustCheckDatabase::class.java)
            .allowMainThreadQueries().build()
        repo = ScanRepositoryImpl(db.scanDao())
    }

    @After fun tearDown() = db.close()

    @Test fun saveAndReadBackWithoutQuery() = runTest {
        val r = engine.analyzeLocally("http://paypal.com.account-verify.top/login?session=secret")
        val id = repo.save(r, TargetType.URL, ScanOrigin.NOTIFICATION, "Messages")
        val rec = repo.get(id)!!
        assertEquals("http://paypal.com.account-verify.top/login", rec.normalizedUrl)
        assertEquals(RiskClassification.SUSPICIOUS, rec.classification)
        assertEquals(r.indicators.map { it.indicator }, rec.indicators.map { it.indicator })
        assertEquals("Messages", rec.sourceApp)
        assertTrue(rec.normalizedUrl!!.contains("secret").not())
    }

    @Test fun searchFilterStatsAndDeletion() = runTest {
        repo.save(engine.analyzeLocally("https://example.com/"), TargetType.URL, ScanOrigin.MANUAL, null)
        val bad = repo.save(engine.analyzeLocally("https://paypa1.com/login"), TargetType.URL, ScanOrigin.MANUAL, null)

        assertEquals(1, repo.observeHistory("paypa1", emptySet()).first().size)
        assertEquals(1, repo.observeHistory("", setOf(RiskClassification.SUSPICIOUS)).first().size)
        val stats = repo.observeStats().first()
        assertEquals(2, stats.total); assertEquals(1, stats.suspicious)
        assertEquals(1, repo.observeRecentAlerts(5).first().size)

        repo.delete(bad)
        assertNull(repo.get(bad))
        repo.clearAll()
        assertEquals(0, repo.observeStats().first().total)
    }

    @Test fun userActionAndRetention() = runTest {
        val id = repo.save(engine.analyzeLocally("https://example.com/"), TargetType.URL, ScanOrigin.MANUAL, null)
        repo.setUserAction(id, UserAction.OPENED_ANYWAY)
        val rec = repo.get(id)!!
        assertEquals(UserAction.OPENED_ANYWAY, rec.userAction)
        assertNotNull(repo.findRecent("https://example.com/", 0))
        assertEquals(1, repo.purgeOlderThan(2_000))
    }

}
