// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

//go:build ignore

//go:generate go run unmarshal_generate.go

package main

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"log"
	"os"
	"strings"
	"text/template"
)

// This file generates rroptsUnmarshalJSON dispatch in unmarshal_generated.go.
// Run with: go generate ./internal/rec/

const (
	inputFile  = "rropts.go"
	outputFile = "unmarshal_generated.go"

	typesTemplate = `// Code generated — DO NOT EDIT.

package rec

import (
	"encoding/json"
	"fmt"
)

// rroptsUnmarshalJSON dispatches JSON unmarshalling to the correct concrete RRopts type.
func rroptsUnmarshalJSON(rrtype RRtype, data json.RawMessage) (RRopts, error) {
	switch rrtype {
	{{- range $tn := .RRoptsNames }}
	case Type{{ $tn }}:
		var opts RRopts{{ $tn }}
		return &opts, json.Unmarshal(data, &opts)
	{{- end }}
	default:
		return nil, fmt.Errorf("unknown rrtype: %s", rrtype)
	}
}
`
)

func main() {
	src, err := os.ReadFile(inputFile)
	if err != nil {
		log.Fatalf("could not read %s: %v", inputFile, err)
	}

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, "", src, parser.ParseComments)
	if err != nil {
		log.Fatalf("could not parse file: %v", err)
	}

	var rroptsNames []string
	for _, decl := range node.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.TYPE {
			continue
		}
		for _, spec := range genDecl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			if _, ok := typeSpec.Type.(*ast.StructType); !ok {
				continue
			}
			typeName := typeSpec.Name.Name
			if !strings.HasPrefix(typeName, "RRopts") {
				continue
			}
			rroptsNames = append(
				rroptsNames,
				strings.TrimPrefix(typeName, "RRopts"),
			)
		}
	}

	tmpl, err := template.New("unmarshal").Parse(typesTemplate)
	if err != nil {
		log.Fatalf("could not parse template: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, struct{ RRoptsNames []string }{rroptsNames}); err != nil {
		log.Fatalf("could not execute template: %v", err)
	}

	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		log.Fatalf("error formatting source: %v", err)
	}

	if err := os.WriteFile(outputFile, formatted, 0o644); err != nil {
		log.Fatalf("could not write %s: %v", outputFile, err)
	}
	log.Printf("generated %s", outputFile)
}
