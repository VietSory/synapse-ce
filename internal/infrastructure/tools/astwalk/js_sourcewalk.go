package astwalk

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	enry "github.com/go-enry/go-enry/v2"
)

// walkJSSourceWithIssues mirrors the bounded source walk but reports every JS/TS candidate that
// cannot be analyzed. The older generic coverage walker intentionally reports only Python candidates,
// so reusing it would let an unreadable .ts file silently look like complete JavaScript coverage.
func walkJSSourceWithIssues(ctx context.Context, root string, visit func(rel, lang string, content []byte), report func(sourceIssue)) (truncated bool, err error) {
	if root == "" { return false, nil }
	files := 0
	walkErr := filepath.WalkDir(root, func(target string, d fs.DirEntry, werr error) error {
		rel := normalizedWalkRelative(root, target)
		candidate := isJSSourcePath(rel)
		if werr != nil {
			if candidate && report != nil { report(sourceIssue{Rel: rel, Reason: sourceIssueUnreadable}) }
			return nil
		}
		if ctx.Err() != nil { return ctx.Err() }
		if d.IsDir() {
			if target != root && skipDirs[d.Name()] { return fs.SkipDir }
			return nil
		}
		if !candidate { return nil }
		if !d.Type().IsRegular() {
			if report != nil { report(sourceIssue{Rel: rel, Reason: sourceIssueSymlink}) }
			return nil
		}
		files++
		if files > maxFiles { truncated = true; return fs.SkipAll }
		fi, lerr := os.Lstat(target)
		if lerr != nil || !fi.Mode().IsRegular() || fi.Size() > int64(maxFileBytes) {
			reason := sourceIssueUnreadable
			if lerr == nil && fi.Size() > int64(maxFileBytes) { reason = sourceIssueOversized }
			if report != nil { report(sourceIssue{Rel: rel, Reason: reason}) }
			return nil
		}
		content, rerr := os.ReadFile(target) // #nosec G304 -- regular, size-capped file under walked root
		if rerr != nil {
			if report != nil { report(sourceIssue{Rel: rel, Reason: sourceIssueUnreadable}) }
			return nil
		}
		if enry.IsVendor(target) || enry.IsDotFile(target) { return nil }
		if enry.IsGenerated(target, content) {
			if report != nil { report(sourceIssue{Rel: rel, Reason: sourceIssueGenerated}) }
			return nil
		}
		if enry.IsBinary(content) {
			if report != nil { report(sourceIssue{Rel: rel, Reason: sourceIssueBinary}) }
			return nil
		}
		lang := "JavaScript"
		switch strings.ToLower(filepath.Ext(target)) {
		case ".ts", ".tsx", ".mts", ".cts":
			lang = "TypeScript"
		}
		visit(filepath.ToSlash(rel), lang, content)
		return nil
	})
	if walkErr != nil { return false, walkErr }
	return truncated, nil
}

func isJSSourcePath(rel string) bool {
	if rel == "" { return false }
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts":
		return true
	}
	return false
}
