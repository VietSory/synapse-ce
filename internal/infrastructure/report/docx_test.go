package report

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"strings"
	"testing"
	"time"
)

func TestDOCXRenderDeterministic(t *testing.T) {
	r := NewDOCXRenderer()
	a, err := r.Render(context.Background(), sampleDoc())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	time.Sleep(1100 * time.Millisecond) // catch any leaked wall-clock in the zip metadata
	b, err := r.Render(context.Background(), sampleDoc())
	if err != nil {
		t.Fatalf("render (second): %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("DOCX render is not byte-deterministic (%d vs %d bytes)", len(a), len(b))
	}
}

func TestDOCXIsValidPackage(t *testing.T) {
	out, err := NewDOCXRenderer().Render(context.Background(), sampleDoc())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatalf("output is not a valid zip: %v", err)
	}
	parts := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		body, _ := io.ReadAll(rc)
		rc.Close()
		parts[f.Name] = string(body)
	}
	for _, required := range []string{"[Content_Types].xml", "_rels/.rels", "word/document.xml", "word/styles.xml", "word/_rels/document.xml.rels"} {
		if _, ok := parts[required]; !ok {
			t.Errorf("docx missing required part %q", required)
		}
	}

	// document.xml must be well-formed XML (Word rejects malformed parts).
	docXML := parts["word/document.xml"]
	dec := xml.NewDecoder(strings.NewReader(docXML))
	for {
		_, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("word/document.xml is not well-formed XML: %v", err)
		}
	}

	// Untrusted finding text must be XML-escaped, never raw markup.
	if strings.Contains(docXML, "<script>alert(1)</script>") {
		t.Error("untrusted finding text was not XML-escaped in document.xml")
	}
	if !strings.Contains(docXML, "&lt;script&gt;") {
		t.Error("expected the script payload to appear escaped in document.xml")
	}
	for _, want := range []string{"Acme &lt;Q3&gt; Report", "Findings Overview", "manual:1", "<w:tbl>"} {
		if !strings.Contains(docXML, want) {
			t.Errorf("document.xml missing expected content %q", want)
		}
	}
}
