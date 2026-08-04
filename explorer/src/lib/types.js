// Shared JSDoc typedefs describing the serialized report payload the
// explorer consumes (explorer contract §4.1). The Pydantic models and the
// exported JSON Schema are the source of truth; these typedefs only name
// the already-validated shapes for the type checker and never widen them.

/**
 * @typedef {'new' | 'dropped' | 'changed'} DiffClass
 * @typedef {'line-span' | 'message' | 'confidence' | 'rule'} ChangedField
 */

/**
 * @typedef {object} SourceExcerpt
 * @property {number} start_line
 * @property {string[]} lines
 * @property {number} omitted_lines
 */

/**
 * @typedef {object} FindingOccurrence
 * @property {string} schema_version
 * @property {number} start_line
 * @property {number} end_line
 * @property {string} message
 * @property {number | null} confidence
 * @property {string | null} rule_id
 * @property {string | null} raw_excerpt
 * @property {SourceExcerpt | null} source_excerpt
 */

/**
 * @typedef {object} FindingLocator
 * @property {string} project
 * @property {string} identity
 * @property {number} line
 * @property {number} occurrence
 */

/**
 * @typedef {object} FindingDiff
 * @property {string} schema_version
 * @property {DiffClass} diff_class
 * @property {string} identity
 * @property {string} tool
 * @property {string} project
 * @property {string} path
 * @property {string | null} symbol
 * @property {string} kind
 * @property {FindingOccurrence | null} base_occurrence
 * @property {FindingOccurrence | null} head_occurrence
 * @property {ChangedField[]} changed_fields
 * @property {FindingLocator | null} locator
 */

/**
 * @typedef {object} DiffTotals
 * @property {number} new
 * @property {number} dropped
 * @property {number} changed
 * @property {number} changed_confidence
 * @property {number} changed_message_only
 */

/**
 * @typedef {object} DiffRollup
 * @property {DiffClass} diff_class
 * @property {string | null} rule_id
 * @property {string | null} kind
 * @property {number} count
 */

/**
 * @typedef {object} ToolError
 * @property {string} side
 * @property {number | null} exit_code
 * @property {string} detail
 */

/**
 * @typedef {object} CorpusIntegrityWarning
 * @property {string} project
 * @property {string} tool
 * @property {string} detail
 */

/**
 * @typedef {object} ProjectReport
 * @property {string} project
 * @property {FindingDiff[]} diffs
 * @property {DiffTotals} totals
 * @property {DiffRollup[]} rollups
 * @property {boolean} truncated
 * @property {number} base_findings
 * @property {number} head_findings
 * @property {number | null} measured_cost_seconds
 * @property {ToolError[]} errors
 * @property {CorpusIntegrityWarning[]} integrity_warnings
 * @property {string[]} source_warnings
 */

/**
 * @typedef {object} EnvironmentRecord
 * @property {string} ref
 * @property {string} sha
 * @property {string} fingerprint
 * @property {string[]} freeze
 * @property {boolean} from_cache
 * @property {boolean} rebuilt
 */

/**
 * @typedef {object} DependencyDelta
 * @property {string} package
 * @property {string | null} base_version
 * @property {string | null} head_version
 */

/**
 * @typedef {object} CorpusPinRecord
 * @property {string} name
 * @property {string} repo
 * @property {string} requested
 * @property {string} resolved_sha
 */

/**
 * @typedef {object} RunManifest
 * @property {string} schema_version
 * @property {string} created_at
 * @property {string} tool
 * @property {string | null} detector_repo
 * @property {EnvironmentRecord | null} base
 * @property {EnvironmentRecord | null} head
 * @property {string[] | null} base_cmd
 * @property {string[] | null} head_cmd
 * @property {boolean} comparable
 * @property {DependencyDelta[]} environment_delta
 * @property {boolean} isolation_enforced
 * @property {string} platform
 * @property {string} python_version
 * @property {string | null} installer
 * @property {CorpusPinRecord[]} corpus_pins
 */

/**
 * @typedef {object} Report
 * @property {string} schema_version
 * @property {RunManifest} manifest
 * @property {ProjectReport[]} projects
 * @property {DiffTotals} totals
 * @property {DiffRollup[]} rollups
 * @property {boolean} truncated
 */

/**
 * @typedef {object} ExplorerReview
 * @property {string} schema_version
 * @property {string} report_sha256
 * @property {FindingLocator[]} selected
 * @property {FindingLocator[]} hidden
 */

export {};
