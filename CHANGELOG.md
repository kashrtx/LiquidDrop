# Changelog

## 5.2.0

- Add **Paste Text** beside Send Folder. Review or edit clipboard text, choose a filename, then send it as a UTF-8 `.txt` file through the existing upload engine.
- Add **Copy text** to received `.txt` files, with a text viewer and manual selection fallback.
- Support manual paste on local HTTP pages and when clipboard permission is denied. Pasting text outside an editor opens a draft without sending automatically.
- Keep cancelled or failed text drafts on the current page. Prevent automatic update reloads from discarding unsent text.
- Validate filenames and limit text sharing to 2 MiB. Text is shared only after pressing Send .txt; no background clipboard synchronization is performed.
- Add browser checks for clipboard reads and writes, HTTP fallback, Unicode, duplicate filenames, failed sends, draft preservation, and mobile layout.

## 5.1.2

- Keep the original file and folder picker selections alive until uploads finish. Previously, the page cleared them before asynchronous sending began.
- Preserve selected files while the Zip & Send choice is open, and release them after sending or cancelling.
- Check the server receipt after a native package upload reports a transport error. If the file was saved, confirm success without reading and uploading it again.
- Describe file-read and transport failures more accurately instead of labelling every failure as a dropped connection.
- Add real-picker and receipt-recovery browser regressions. Fast streaming uploads remain unchanged.

**Known limitation:** Some RTFD selections remain unreadable through iOS Safari or the Files provider. This release does not claim to resolve that platform-specific issue. Exporting as RTF/PDF or selecting an explicitly compressed copy can help.

## 5.1.1

- Fix sending native Apple RTFD packages from Safari. These can report a zero JavaScript file size before WebKit generates the package archive during multipart upload. Keep the original File intact and let the browser serialize its contents.
- Count actual received bytes instead of rejecting a package based on its reported size. Still reject genuinely empty received packages.
- Keep package retries idempotent after a lost reply, including packages uploaded through Zip & Send. Use the received byte count when creating the final archive.
- Wrap long status messages on mobile so errors remain readable.

## 5.1.0

- Recognize Apple RTFD documents and `.rtfd.zip` packages. Preview their rich-text content as readable plain text while preserving the original package and attachments.
- Report RTFD exports containing no received bytes as failures with recovery instructions, rather than publishing a zero-byte note. Existing received files are left intact.
- Add **Send Folder** and recursive folder drag-and-drop. Upload file data with the existing fast streaming/recovery engine; build one archive on the computer with nested paths intact. Drag-and-drop also preserves empty folders.
- Make Zip & Send use private staging and all-or-nothing archive creation. Failed transfers no longer silently create incomplete archives or leave loose files in the shared list. Repeated bundling requests return the original archive after a lost reply.
- Preserve identically named files from different folders; disambiguate duplicate names in ordinary Zip & Send batches. Reject unsafe archive paths.
- Limit folder batches to 5000 entries and document previews to bounded sizes. Native folder-picker availability depends on the browser; empty-folder selection requires drag-and-drop.

## 5.0.3

- Restore native file streaming for healthy connections. Large videos no longer copy every 8 MiB into JavaScript memory and wait for a separate upload response per piece.
- Automatically switch an interrupted native upload to the bounded 8 MiB recovery path, resuming from the computer's saved offset. The 5.0.2 request deadlines and finalization fixes remain in place.
- Check server progress immediately when the browser finishes sending, reducing waits when the upload response is lost.
- Remove the extra file-read probe on network errors; transient read failures remain retryable.
- Add regressions for stalled native file providers and healthy uploads that must avoid JavaScript file reads and use one request. Add an optional 128 MiB browser throughput benchmark.

## 5.0.2

- Bound upload creation, status, and finalization requests, including response-body reads. Missing replies now trigger automatic retries instead of waiting indefinitely.
- Read files in bounded 8 MiB pieces before sending them, avoiding direct transfer of live Files-provider-backed files to the browser's network process. File reads have a timeout too.
- Recover from a missing upload response as soon as the computer confirms the piece was saved. Silent connections resume without tapping the sending bar.
- Serialize completion metadata checks with finalization so concurrent retries return the original saved filename instead of incorrectly reporting zero bytes.
- Keep upload synchronization shared while retries are waiting. Cancellation no longer removes upload files if it cannot acquire the lock.
- Show 100% only after finalization succeeds; failed uploads show a failure message.
- Add single-MP4, mixed-document/multiple-video, hung-file-read, lost-response, and concurrent-completion regression tests. Real Chromium tests verify transferred file hashes, automatic recovery, and disk-full reporting.
- Gate release downloads on Rust and upload recovery tests, real-browser transfer tests, and native Windows transfer tests.
