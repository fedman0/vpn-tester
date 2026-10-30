package com.arad.vpn_tester.scan

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.DocumentsContract.Document

data class FolderFile(val path: String, val uri: Uri, val size: Long, val mime: String)

object FolderScanner {

    const val MAX_FILE_BYTES = 4L * 1024 * 1024
    const val MAX_FILES = 20_000

    private val skipMimePrefixes = listOf("image/", "video/", "audio/", "font/")
    private val skipExtensions = setOf(
        "apk", "apks", "xapk", "aab", "zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "zst",
        "mp4", "mkv", "avi", "mov", "webm", "mp3", "m4a", "ogg", "flac", "wav", "opus",
        "jpg", "jpeg", "png", "gif", "webp", "bmp", "heic", "svg", "ico",
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt",
        "exe", "dll", "so", "dex", "jar", "class", "iso", "img", "bin", "db", "sqlite",
    )

    fun list(
        context: Context,
        tree: Uri,
        recursive: Boolean,
        isActive: () -> Boolean,
        onProgress: (Int) -> Unit,
    ): List<FolderFile> {
        val cr = context.contentResolver
        val out = ArrayList<FolderFile>()
        val queue = ArrayDeque<Pair<String, String>>()
        queue.add(DocumentsContract.getTreeDocumentId(tree) to "")
        val projection = arrayOf(
            Document.COLUMN_DOCUMENT_ID,
            Document.COLUMN_DISPLAY_NAME,
            Document.COLUMN_MIME_TYPE,
            Document.COLUMN_SIZE,
        )
        while (queue.isNotEmpty() && out.size < MAX_FILES && isActive()) {
            val (docId, prefix) = queue.removeFirst()
            val children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, docId)
            runCatching {
                cr.query(children, projection, null, null, null)?.use { c ->
                    while (c.moveToNext()) {
                        val id = c.getString(0) ?: continue
                        val name = c.getString(1) ?: continue
                        val mime = c.getString(2) ?: ""
                        val size = if (c.isNull(3)) -1L else c.getLong(3)
                        if (mime == Document.MIME_TYPE_DIR) {
                            if (recursive && !name.startsWith(".")) queue.add(id to "$prefix$name/")
                            continue
                        }
                        if (!wanted(name, mime, size)) continue
                        out.add(FolderFile("$prefix$name", DocumentsContract.buildDocumentUriUsingTree(tree, id), size, mime))
                        if (out.size % 50 == 0) onProgress(out.size)
                    }
                }
            }
        }
        onProgress(out.size)
        return out
    }

    private fun wanted(name: String, mime: String, size: Long): Boolean {
        if (size > MAX_FILE_BYTES) return false
        if (size == 0L) return false
        val ext = name.substringAfterLast('.', "").lowercase()
        if (ext in skipExtensions) return false
        if (skipMimePrefixes.any { mime.startsWith(it) }) return false
        return true
    }

    fun read(context: Context, uri: Uri): ByteArray? = runCatching {
        context.contentResolver.openInputStream(uri)?.use { input ->
            val buf = java.io.ByteArrayOutputStream()
            val chunk = ByteArray(64 * 1024)
            var total = 0L
            while (true) {
                val n = input.read(chunk)
                if (n < 0) break
                total += n
                if (total > MAX_FILE_BYTES) return@runCatching null
                buf.write(chunk, 0, n)
            }
            buf.toByteArray()
        }
    }.getOrNull()

    fun label(tree: Uri): String {
        val id = runCatching { DocumentsContract.getTreeDocumentId(tree) }.getOrNull() ?: return tree.toString()
        val volume = id.substringBefore(':')
        val path = id.substringAfter(':', "")
        val root = when {
            volume.equals("primary", ignoreCase = true) -> "Internal storage"
            volume.equals("home", ignoreCase = true) -> "Documents"
            volume.startsWith("raw") -> return path.ifEmpty { id }
            else -> "SD card ($volume)"
        }
        return if (path.isEmpty()) root else "$root/$path"
    }
}
