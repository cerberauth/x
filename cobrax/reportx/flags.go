package reportx

import (
	"fmt"
	"io"
	"os"

	"github.com/cerberauth/reportx/format"
	"github.com/cerberauth/reportx/transport"
	"github.com/spf13/cobra"
)

// RegisterFormatFlags binds --format, --output, and --no-color to cmd.
func RegisterFormatFlags(cmd *cobra.Command) {
	cmd.Flags().String("format", string(format.FormatTerminal),
		fmt.Sprintf("output format: %s", formatChoices()))
	cmd.Flags().String("output", "",
		"file path to write the report (stdout if empty)")
	cmd.Flags().Bool("no-color", false,
		"disable ANSI colors in terminal output")
}

// RegisterTransportFlags binds --report-url and --report-header to cmd.
func RegisterTransportFlags(cmd *cobra.Command) {
	cmd.Flags().String("report-url", "",
		"HTTP endpoint to POST the report to")
	cmd.Flags().StringToString("report-header", nil,
		"additional HTTP headers for the report transport (key=value)")
}

// FormatterFromFlags reads --format and --no-color and returns a Formatter.
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
