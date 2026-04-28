package redactlog

// pciRedactPaths is the set of Pino-style DSL paths that the PCI preset
// redacts by field name. These cover the most common field names used by
// payment libraries and webhook bodies for PANs, CVVs, and track data.
// Content-based PAN detection (via PANDetector) complements these path rules
// for PANs that appear in unstructured string values.
//
// Per ADR-002: paths use the Pino-style DSL subset (dot notation, wildcards,
// bracket form for hyphenated keys). Per ADR-008: all matched values are
// replaced with the single censor token "***".
var pciRedactPaths = []string{
	// Card verification values — always redact; no display exception in PCI DSS.
	"*.cvv",
	"*.cvv2",
	"*.cvc",
	"*.cvc2",
	"*.pin",

	// Primary Account Numbers by common field names. Content detection via
	// PANDetector handles PANs in unstructured fields.
	"*.pan",
	"*.card_number",
	"*.cardNumber",
	"*.account_number",
	"*.accountNumber",

	// Magnetic stripe track data.
	"*.track1",
	"*.track2",
	"*.track_data",
	"*.trackData",

	// Card object sub-paths used by Stripe, Adyen, and Square SDKs.
	"*.card.number",
	"*.card.cvv",
	"*.card.cvc",
	"*.card.pin",
	"*.payment.card.*",
	"*.payment_method.card.number",
}

// pciHeaderDenylist contains the HTTP headers the PCI preset adds to the
// denylist on top of the middleware's built-in defaults. These are merged with
// WithHeaderDenylist, which appends to (not replaces) the default list.
var pciHeaderDenylist = []string{
	"authorization",
	"cookie",
	"set-cookie",
}
