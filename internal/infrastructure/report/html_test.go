package report

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func sampleDoc() ports.ReportDocument {
	return ports.ReportDocument{
		Title:       "Acme <Q3> Report",
		Subtitle:    "Client: Acme  ·  Synapse v1.2.3",
		GeneratedAt: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC),
		Version:     "v1.2.3",
		Sections: []ports.ReportSection{
			{Heading: "Executive Summary", Paragraphs: []string{"Line one.", "Has markup <script>alert(1)</script> & ampersand."}},
			{Heading: "Findings Overview", Table: &ports.ReportTable{
				Headers: []string{"ID", "Title"},
				Rows:    [][]string{{"manual:1", "Stored XSS <b>"}, {"manual:2", "SQLi"}},
			}},
		},
	}
}

func TestHTMLRenderDeterministic(t *testing.T) {
	r := NewHTMLRenderer()
	a, err := r.Render(context.Background(), sampleDoc())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	time.Sleep(1100 * time.Millisecond) // a leaking time.Now() would diverge the bytes
	b, err := r.Render(context.Background(), sampleDoc())
	if err != nil {
		t.Fatalf("render (second): %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("HTML render is not byte-deterministic (%d vs %d bytes)", len(a), len(b))
	}
}

func TestHTMLRenderEscapesInjection(t *testing.T) {
	out, err := NewHTMLRenderer().Render(context.Background(), sampleDoc())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(out)
	if strings.Contains(s, "<script>alert(1)</script>") {
		t.Error("untrusted finding text was not HTML-escaped (raw <script> present)")
	}
	if !strings.Contains(s, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("expected the script payload to appear escaped")
	}
	if !strings.Contains(s, "<title>Acme &lt;Q3&gt; Report</title>") {
		t.Error("title not escaped in <title>")
	}
	for _, want := range []string{"<h1>", "Findings Overview", "<th>ID</th>", "manual:1", "no AI in the report path"} {
		if !strings.Contains(s, want) {
			t.Errorf("HTML missing expected content %q", want)
		}
	}
}
