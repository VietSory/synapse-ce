package ownadvisory

// Ingestion safety caps shared by BOTH advisory feeds (DirFeed + RemoteFeed): they bound per-entry
// decompressed size (oversized-file / zip-bomb guard), the total entry/file count (runaway tree or
// many-entry zip), and a single remote zip download (disk-bomb). Kept here, not in either feed file, so the
// cross-feed sharing is explicit rather than governed by a comment scoped to one feed.
const (
	maxAdvisoryBytes = 8 << 20   // per-entry / per-file decompressed cap (a single OSV advisory JSON is KBs)
	maxAdvisoryFiles = 2_000_000 // entry/file-count cap (bounds a runaway dir tree or a many-entry zip)
	maxZipDownload   = 1 << 30   // 1 GiB cap on a single ecosystem's all.zip download (RemoteFeed only)
)
