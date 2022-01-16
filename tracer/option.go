package tracer

import (
	"io"
	"os"
	"strings"
)

type Option interface {
	apply(*config)
}

type ExporterName int

const (
	ExporterNone ExporterName = iota
	ExporterJaeger
	ExporterJSON
)

func envExporterName() ExporterName {
	name := os.Getenv("OTEL_EXPORTER")
	switch strings.ToLower(name) {
	case "jaeger":
		return ExporterJaeger
	case "json":
		return ExporterJSON
	default:
		return ExporterNone
	}
}

type config struct {
	writer       io.Writer
	exporterName ExporterName
	filename     string
}

func WithWriter(w io.Writer) Option {
	return writerOption{w}
}

func WithExporter(name ExporterName) Option {
	return exporter{name}
}

func WithFileName(name string) Option {
	return file{name}
}

type writerOption struct {
	W io.Writer
}

func (w writerOption) apply(conf *config) {
	conf.writer = w.W
}

type exporter struct {
	name ExporterName
}

func (e exporter) apply(conf *config) {
	conf.exporterName = e.name
}

type file struct {
	filename string
}

func (f file) apply(conf *config) {
	conf.filename = f.filename
}
