package com.arad.vpn_tester.scan

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.DocumentsContract.Document

data class ExportItem(val path: String, val data: () -> ByteArray?)

data class ExportReport(val written: Int, val failed: List<String>)

interface ConfigExporter {
    fun export(items: List<ExportItem>, destination: Uri): ExportReport
}

class SafConfigExporter(private val context: Context) : ConfigExporter {

    private val cr get() = context.contentResolver

    override fun export(items: List<ExportItem>, destination: Uri): ExportReport {
        val rootDoc = DocumentsContract.buildDocumentUriUsingTree(destination, DocumentsContract.getTreeDocumentId(destination))
        val dirs = HashMap<String, Uri>()
        dirs[""] = rootDoc
        val listings = HashMap<Uri, MutableMap<String, Uri>>()
        var written = 0
        val failed = ArrayList<String>()
        for (item in items.distinctBy { it.path }) {
            val ok = runCatching {
                val clean = item.path.split('/').filter { it.isNotEmpty() && it != "." && it != ".." }
                if (clean.isEmpty()) error("empty path")
                var dir = rootDoc
                var key = ""
                for (seg in clean.dropLast(1)) {
                    key = if (key.isEmpty()) seg else "$key/$seg"
                    dir = dirs.getOrPut(key) { findOrCreate(destination, dir, seg, true, listings) }
                }
                val data = item.data() ?: error("cannot read source")
                val file = findOrCreate(destination, dir, clean.last(), false, listings)
                cr.openOutputStream(file, "wt")?.use { it.write(data) } ?: error("cannot open destination")
            }.isSuccess
            if (ok) written++ else failed.add(item.path)
        }
        return ExportReport(written, failed)
    }

    private fun children(tree: Uri, dir: Uri, listings: HashMap<Uri, MutableMap<String, Uri>>): MutableMap<String, Uri> =
        listings.getOrPut(dir) {
            val map = HashMap<String, Uri>()
            val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(tree, DocumentsContract.getDocumentId(dir))
            runCatching {
                cr.query(childrenUri, arrayOf(Document.COLUMN_DOCUMENT_ID, Document.COLUMN_DISPLAY_NAME), null, null, null)?.use { c ->
                    while (c.moveToNext()) {
                        val id = c.getString(0) ?: continue
                        val name = c.getString(1) ?: continue
                        map[name] = DocumentsContract.buildDocumentUriUsingTree(tree, id)
                    }
                }
            }
            map
        }

    private fun findOrCreate(tree: Uri, dir: Uri, name: String, isDir: Boolean, listings: HashMap<Uri, MutableMap<String, Uri>>): Uri {
        val existing = children(tree, dir, listings)
        existing[name]?.let { return it }
        val mime = if (isDir) Document.MIME_TYPE_DIR else "application/octet-stream"
        val created = DocumentsContract.createDocument(cr, dir, mime, name) ?: error("cannot create $name")
        existing[name] = created
        return created
    }
}
