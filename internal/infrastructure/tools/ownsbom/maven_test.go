package ownsbom

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

const pomFixture = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>

  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-bom</artifactId>
        <version>6.0.0</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>

  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.14.0</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>${spring.version}</version>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>managed-dep</artifactId>
    </dependency>
  </dependencies>
</project>
`

func TestMavenParse(t *testing.T) {
	comps, deps, err := Maven{}.Parse(context.Background(), ParseInput{Path: "pom.xml", Content: []byte(pomFixture)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if deps != nil {
		t.Errorf("edges deferred; want nil deps, got %v", deps)
	}
	byName := map[string]sbom.Component{}
	for _, c := range comps {
		byName[c.Name] = c
	}
	// literal-version direct dep -> group:artifact name + pkg:maven/group/artifact PURL, production scope
	if c := byName["org.apache.commons:commons-lang3"]; c.Version != "3.14.0" ||
		c.PURL != "pkg:maven/org.apache.commons/commons-lang3@3.14.0" || c.Scope != sbom.ScopeProduction {
		t.Errorf("commons-lang3 = %+v", c)
	}
	// <scope>test</scope> -> background test scope
	if c := byName["junit:junit"]; c.Version != "4.13.2" || c.Scope != sbom.ScopeTest {
		t.Errorf("junit = %+v, want 4.13.2 / test scope", c)
	}
	// a ${property} version is unresolved -> skipped (not emitted with the literal "${…}")
	if _, ok := byName["org.springframework:spring-core"]; ok {
		t.Error("a ${property}-versioned dep must be skipped (unresolved)")
	}
	// a dep with no <version> (parent/BOM-managed) -> skipped
	if _, ok := byName["org.example:managed-dep"]; ok {
		t.Error("a BOM/parent-managed dep (no <version>) must be skipped (unresolved)")
	}
	// the <dependencyManagement> BOM is version constraints, NOT real deps -> never emitted
	if _, ok := byName["org.springframework:spring-bom"]; ok {
		t.Error("a <dependencyManagement> entry must not be emitted as a component")
	}
	if len(comps) != 2 {
		t.Fatalf("want 2 components (commons-lang3, junit), got %d: %+v", len(comps), comps)
	}
}
