// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.ocr

import android.content.Context
import android.graphics.Bitmap
import android.net.Uri
import com.google.mlkit.vision.common.InputImage
import com.google.mlkit.vision.text.TextRecognition
import com.google.mlkit.vision.text.latin.TextRecognizerOptions
import kotlinx.coroutines.tasks.await
import java.io.IOException

/**
 * On-device OCR (ML Kit, bundled Latin model) for shared screenshots. Images never leave the
 * device. URLs are almost always Latin-script, so the Latin model works for all UI languages;
 * scam phrases in non-Latin scripts in images are not recognized (documented limitation).
 */
class OcrTextExtractor(private val context: Context) {
    sealed interface Outcome {
        data class Text(val value: String) : Outcome
        data object NoText : Outcome
        data class Failed(val reason: String) : Outcome
    }

    suspend fun extract(uri: Uri): Outcome {
        val image = try { InputImage.fromFilePath(context, uri) } catch (e: IOException) { return Outcome.Failed("io") }
        return recognize(image)
    }

    /** OCR for rendered PDF pages. */
    suspend fun extract(bitmap: Bitmap): Outcome = recognize(InputImage.fromBitmap(bitmap, 0))

    private suspend fun recognize(image: InputImage): Outcome {
        val recognizer = TextRecognition.getClient(TextRecognizerOptions.DEFAULT_OPTIONS)
        return try {
            val text = recognizer.process(image).await().text
            if (text.isBlank()) Outcome.NoText else Outcome.Text(text)
        } catch (e: IOException) {
            Outcome.Failed("io")
        } catch (e: Exception) {
            Outcome.Failed(e.javaClass.simpleName)
        } finally {
            recognizer.close()
        }
    }
}
