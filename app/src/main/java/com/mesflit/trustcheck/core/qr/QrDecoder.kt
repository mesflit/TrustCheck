// TrustCheck — Copyright (C) 2026 Mesflit — SPDX-License-Identifier: GPL-3.0-only
package com.mesflit.trustcheck.core.qr

import android.content.Context
import android.graphics.Bitmap
import android.net.Uri
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import com.google.mlkit.vision.common.InputImage
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.tasks.await
import java.io.IOException
import kotlin.coroutines.resume

/**
 * QR / barcode reading, entirely on the device.
 *
 * Camera: Google's code scanner shows its own camera screen through Google Play services, so
 * TrustCheck needs **no camera permission** and never sees camera images — only the decoded text.
 * Images: ML Kit decodes QR codes in shared screenshots and photos.
 * The decoded content is only analyzed; a link in a QR code is never opened automatically.
 */
class QrDecoder(private val context: Context) {

    sealed interface CameraResult {
        data class Value(val text: String) : CameraResult
        data object Cancelled : CameraResult
        data class Unavailable(val reason: String) : CameraResult
    }

    private val formats = BarcodeScannerOptions.Builder()
        .setBarcodeFormats(Barcode.FORMAT_QR_CODE, Barcode.FORMAT_AZTEC, Barcode.FORMAT_DATA_MATRIX, Barcode.FORMAT_PDF417)
        .build()

    suspend fun scanWithCamera(): CameraResult {
        val options = GmsBarcodeScannerOptions.Builder()
            .setBarcodeFormats(Barcode.FORMAT_QR_CODE, Barcode.FORMAT_AZTEC, Barcode.FORMAT_DATA_MATRIX)
            .build()
        val scanner = GmsBarcodeScanning.getClient(context, options)
        return suspendCancellableCoroutine { cont ->
            scanner.startScan()
                .addOnSuccessListener { b -> if (cont.isActive) cont.resume(b.rawValue?.takeIf { it.isNotBlank() }?.let { CameraResult.Value(it) } ?: CameraResult.Cancelled) }
                .addOnCanceledListener { if (cont.isActive) cont.resume(CameraResult.Cancelled) }
                .addOnFailureListener { e -> if (cont.isActive) cont.resume(CameraResult.Unavailable(e.javaClass.simpleName)) }
        }
    }

    /** Decoded values of all codes in an image (empty if none or unreadable). */
    suspend fun decode(uri: Uri): List<String> =
        try { decode(InputImage.fromFilePath(context, uri)) } catch (e: IOException) { emptyList() }

    suspend fun decode(bitmap: Bitmap): List<String> = decode(InputImage.fromBitmap(bitmap, 0))

    private suspend fun decode(image: InputImage): List<String> {
        val client = BarcodeScanning.getClient(formats)
        return try {
            client.process(image).await().mapNotNull { it.rawValue?.takeIf(String::isNotBlank) }.distinct()
        } catch (e: Exception) {
            emptyList()
        } finally {
            client.close()
        }
    }
}
