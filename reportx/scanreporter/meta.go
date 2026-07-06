package scanreporter

// ScanMeta carries scan-level context passed to Reporter.Report.
type ScanMeta struct {
	Target         string
	BaselineStatus int
	Offline        bool
}
