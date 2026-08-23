package reportx

import (
	"fmt"
	"io"
	"os"

	"github.com/cerberauth/reportx/format"
	"github.com/cerberauth/reportx/transport"
	"github.com/spf13/cobra"

	"github.com/cerberauth/x/reportx/harnessreport"
)

// RegisterFormatFlags binds --format, --no-color, --quiet, --output, and
// --output-format to cmd. It is idempotent with respect to flags already
// defined on cmd (e.g. by another flag-registration helper sharing the same
// flag set) - an existing flag of the same name is left as-is rather than
// causing a duplicate-registration panic.
func RegisterFormatFlags(cmd *cobra.Command) {
	if cmd.Flags().Lookup("format") == nil {
		cmd.Flags().String("format", string(format.FormatTerminal),
			fmt.Sprintf("terminal display format: %s", formatChoices()))
	}
	if cmd.Flags().Lookup("no-color") == nil {
		cmd.Flags().Bool("no-color", false,
			"disable ANSI colors in terminal output")
	}
	if cmd.Flags().Lookup("quiet") == nil {
		cmd.Flags().Bool("quiet", false,
			"suppress terminal display of the report")
	}
	if cmd.Flags().Lookup("output") == nil {
		cmd.Flags().String("output", "",
			"file path to additionally write the report to")
	}
	if cmd.Flags().Lookup("output-format") == nil {
		cmd.Flags().String("output-format", string(format.FormatJSON),
			fmt.Sprintf("format for --output: %s", formatChoices()))
	}
}

// RegisterTransportFlags binds --report-url, --report-header, and
// --report-format to cmd. See RegisterFormatFlags for the idempotency note.
func RegisterTransportFlags(cmd *cobra.Command) {
	if cmd.Flags().Lookup("report-url") == nil {
		cmd.Flags().String("report-url", "",
			"HTTP endpoint to POST the report to")
	}
	if cmd.Flags().Lookup("report-header") == nil {
		cmd.Flags().StringToString("report-header", nil,
			"additional HTTP headers for the report transport (key=value)")
	}
	if cmd.Flags().Lookup("report-format") == nil {
		cmd.Flags().String("report-format", string(format.FormatJSON),
			fmt.Sprintf("format for --report-url: %s", formatChoices()))
	}
}

// FormatterFromFlags reads --format and --no-color and returns a Formatter
// for the terminal display sink.
func FormatterFromFlags(cmd *cobra.Command) (format.Formatter, error) {
	f, err := cmd.Flags().GetString("format")
	if err != nil {
		return nil, err
	}
	noColor, err := cmd.Flags().GetBool("no-color")
	if err != nil {
		return nil, err
	}
	if (format.FormatName(f) == format.FormatTerminal || f == "text" || f == "plain") && noColor {
		return format.NewTerminalFormatterNoColor(), nil
	}
	return format.NewFormatter(f)
}

// WriterFromFlags opens the destination specified by --output (stdout if empty).
// The caller must invoke the returned cleanup func when done.
func WriterFromFlags(cmd *cobra.Command) (io.Writer, func(), error) {
	path, err := cmd.Flags().GetString("output")
	if err != nil {
		return nil, nil, err
	}
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reportx: create output file: %w", err)
	}
	return file, func() { file.Close() }, nil
}

// HTTPTransportFromFlags builds an HTTPTransport from --report-url and --report-header.
// Returns nil, nil when --report-url is not set.
func HTTPTransportFromFlags(cmd *cobra.Command) (*transport.HTTPTransport, error) {
	url, err := cmd.Flags().GetString("report-url")
	if err != nil {
		return nil, err
	}
	if url == "" {
		return nil, nil
	}
	headers, err := cmd.Flags().GetStringToString("report-header")
	if err != nil {
		return nil, err
	}
	t := transport.NewHTTPTransport(url)
	if len(headers) > 0 {
		t.Headers = headers
	}
	return t, nil
}

// SinksFromFlags builds every delivery sink requested via flags: a terminal
// sink to stdout (unless --quiet), a file sink when --output is set, and an
// HTTP sink when --report-url is set - each with its own format, and all
// delivered together in a single scan. The caller must invoke the returned
// cleanup func when done (it closes any file opened for --output).
func SinksFromFlags(cmd *cobra.Command) ([]harnessreport.Sink, func(), error) {
	var sinks []harnessreport.Sink
	cleanup := func() {}

	quiet, err := cmd.Flags().GetBool("quiet")
	if err != nil {
		return nil, cleanup, err
	}
	if !quiet {
		f, err := FormatterFromFlags(cmd)
		if err != nil {
			return nil, cleanup, err
		}
		sinks = append(sinks, harnessreport.Sink{Formatter: f, Writer: os.Stdout})
	}

	outputSink, outputCleanup, err := outputSinkFromFlags(cmd)
	if err != nil {
		return nil, cleanup, err
	}
	if outputSink != nil {
		cleanup = outputCleanup
		sinks = append(sinks, *outputSink)
	}

	transportSink, err := transportSinkFromFlags(cmd)
	if err != nil {
		return nil, cleanup, err
	}
	if transportSink != nil {
		sinks = append(sinks, *transportSink)
	}

	return sinks, cleanup, nil
}

func outputSinkFromFlags(cmd *cobra.Command) (*harnessreport.Sink, func(), error) {
	outputPath, err := cmd.Flags().GetString("output")
	if err != nil {
		return nil, nil, err
	}
	if outputPath == "" {
		return nil, nil, nil
	}

	outputFormat, err := cmd.Flags().GetString("output-format")
	if err != nil {
		return nil, nil, err
	}
	f, err := format.NewFormatter(outputFormat)
	if err != nil {
		return nil, nil, err
	}
	file, err := os.Create(outputPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reportx: create output file: %w", err)
	}
	return &harnessreport.Sink{Formatter: f, Writer: file}, func() { file.Close() }, nil
}

func transportSinkFromFlags(cmd *cobra.Command) (*harnessreport.Sink, error) {
	tr, err := HTTPTransportFromFlags(cmd)
	if err != nil {
		return nil, err
	}
	if tr == nil {
		return nil, nil
	}
	reportFormat, err := cmd.Flags().GetString("report-format")
	if err != nil {
		return nil, err
	}
	f, err := format.NewFormatter(reportFormat)
	if err != nil {
		return nil, err
	}
	return &harnessreport.Sink{Formatter: f, Transport: tr}, nil
}

func formatChoices() string {
	names := make([]string, len(format.FormatNames))
	for i, n := range format.FormatNames {
		names[i] = string(n)
	}
	result := ""
	for i, n := range names {
		if i > 0 {
			result += " | "
		}
		result += n
	}
	return result
}
