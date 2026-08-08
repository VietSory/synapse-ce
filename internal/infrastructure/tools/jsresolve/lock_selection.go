package jsresolve

// lockSelectionUnsupported records that an applicable lock/importer entry was
// observed for a package name but could not be interpreted safely. Keeping it
// in the selection set prevents R2C from falling through to a unique SBOM name
// match and accidentally turning malformed/unsupported lock metadata into
// false confidence.
const lockSelectionUnsupported lockSelectionKind = 3
