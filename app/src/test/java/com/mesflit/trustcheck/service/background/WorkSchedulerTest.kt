package com.mesflit.trustcheck.service.background

import android.app.Application
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.work.Configuration
import androidx.work.WorkInfo
import androidx.work.WorkManager
import androidx.work.testing.SynchronousExecutor
import androidx.work.testing.WorkManagerTestInitHelper
import com.mesflit.trustcheck.core.security.UrlAnalysisEngine
import com.mesflit.trustcheck.domain.AppSettings
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class WorkSchedulerTest {
    private lateinit var context: Context
    private lateinit var wm: WorkManager

    @Before fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        WorkManagerTestInitHelper.initializeTestWorkManager(context, Configuration.Builder().setExecutor(SynchronousExecutor()).build())
        wm = WorkManager.getInstance(context)
    }

    private fun active(name: String) = wm.getWorkInfosForUniqueWork(name).get().filter { !it.state.isFinished }

    @Test fun schedulesRetentionAndThreatFeedOnlyWhenEnabled() {
        val s = WorkScheduler(context)
        s.schedulePeriodic(AppSettings(threatFeed = true), firstFeedNeeded = true)
        assertEquals(1, active(WorkScheduler.WORK_RETENTION).size)
        assertEquals(1, active(WorkScheduler.WORK_FEED).size)
        assertEquals(1, active(WorkScheduler.WORK_FEED_NOW).size) // first download on any network

        s.schedulePeriodic(AppSettings(threatFeed = false))
        assertTrue(active(WorkScheduler.WORK_FEED).isEmpty())
        assertTrue(active(WorkScheduler.WORK_FEED_NOW).isEmpty())
    }

    @Test fun duplicateDeferredScansAreCollapsed() {
        val s = WorkScheduler(context)
        val local = UrlAnalysisEngine().analyzeLocally("https://bit.ly/abc?x=1")
        repeat(3) { s.enqueueDeferredScan(local, 7L, "Messages") }
        val infos = wm.getWorkInfosForUniqueWork(WorkScheduler.uniqueScanName(local.normalizedUrl!!)).get()
        assertEquals(1, infos.size)
        assertEquals(WorkInfo.State.ENQUEUED, infos.single().state) // waits for network constraint
    }

    @Test fun uniqueNameIsStableAndIgnoresQuery() {
        assertEquals(WorkScheduler.uniqueScanName("https://a.com/x"), WorkScheduler.uniqueScanName("https://a.com/x"))
        val a = UrlAnalysisEngine().analyzeLocally("https://a.com/x?t=1").normalizedUrl!!
        val b = UrlAnalysisEngine().analyzeLocally("https://a.com/x?t=2").normalizedUrl!!
        assertEquals(WorkScheduler.uniqueScanName(a), WorkScheduler.uniqueScanName(b))
    }
}
