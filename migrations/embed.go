// Package migrations embeds the SQL migration files so the server can apply them
// at startup via goose (no external migration tool needed for self-host).
package migrations

import "embed"

// FS holds the goose SQL migrations (applied with dialect "postgres").
//
//go:embed *.sql
var FS embed.FS
