package harnessreport

// Result is a single check's outcome from a harnessx-based vulnerability scan.
type Result struct {
	Name        string
	Payload     string // the crafted value used for this check attempt
	Status      int
	Vulnerable  bool
	Err         error
	Skipped     bool
	SkipReason  string
	Extra       string
	CVSSVector  string
	CVSSScore   float64
	CWEID       string
	OWASP       string
	Link        string
	Description string
}
