# Changelog

## 5.0.2

- Bound upload creation, status, and finalization requests, including response-body reads. Missing replies now trigger automatic retries instead of waiting indefinitely.
- Read files in bounded 8 MiB pieces before sending them, avoiding direct transfer of live Files-provider-backed files to the browser's network process. File reads have a timeout too.
- Recover from a missing upload response as soon as the computer confirms the piece was saved. Silent connections resume without tapping the sending bar.
- Serialize completion metadata checks with finalization so concurrent retries return the original saved filename instead of incorrectly reporting zero bytes.
- Keep upload synchronization shared while retries are waiting. Cancellation no longer removes upload files if it cannot acquire the lock.
- Show 100% only after finalization succeeds; failed uploads show a failure message.
- Add single-MP4, mixed-document/multiple-video, hung-file-read, lost-response, and concurrent-completion regression tests. Real Chromium tests verify transferred file hashes, automatic recovery, and disk-full reporting.
- Gate release downloads on Rust and upload recovery tests, real-browser transfer tests, and native Windows transfer tests.
