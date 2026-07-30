// GENERATED FILE - do not edit by hand.
// Regenerate with: node explorer/generate-schemas.mjs
// Source of truth: liveness_primer/schemas/*.schema.json (contract §7).

export const REPORT_SCHEMA = {
  "$defs": {
    "ChangedField": {
      "description": "Observable occurrence field that may differ within a ``changed`` diff (contract §8).\n\nAttributes\n----------\nLINE_SPAN\n    The start/end line span moved.\nMESSAGE\n    The message text changed.\nCONFIDENCE\n    The confidence value changed (only for tools declaring the capability).\nRULE\n    The detector rule ID changed (reporting contract §3.1).",
      "enum": [
        "line-span",
        "message",
        "confidence",
        "rule"
      ],
      "title": "ChangedField",
      "type": "string"
    },
    "CorpusIntegrityWarning": {
      "additionalProperties": false,
      "description": "Corpus-integrity warning for an expected-clean pair (contract §5).\n\nAttributes\n----------\nproject : str\n    Corpus project name.\ntool : str\n    Adapter name.\ndetail : str\n    What the base side reported (findings or nonzero exit).",
      "properties": {
        "detail": {
          "title": "Detail",
          "type": "string"
        },
        "project": {
          "title": "Project",
          "type": "string"
        },
        "tool": {
          "title": "Tool",
          "type": "string"
        }
      },
      "required": [
        "project",
        "tool",
        "detail"
      ],
      "title": "CorpusIntegrityWarning",
      "type": "object"
    },
    "CorpusPinRecord": {
      "additionalProperties": false,
      "description": "Resolved pin for one corpus project in one run (contract §3).\n\nAttributes\n----------\nname : str\n    Corpus project name.\nrepo : str\n    Repository URL.\nrequested : str\n    The pin SHA or ``branch:<name>`` selector from the corpus file.\nresolved_sha : str\n    Commit SHA both revisions analyzed.",
      "properties": {
        "name": {
          "title": "Name",
          "type": "string"
        },
        "repo": {
          "title": "Repo",
          "type": "string"
        },
        "requested": {
          "title": "Requested",
          "type": "string"
        },
        "resolved_sha": {
          "title": "Resolved Sha",
          "type": "string"
        }
      },
      "required": [
        "name",
        "repo",
        "requested",
        "resolved_sha"
      ],
      "title": "CorpusPinRecord",
      "type": "object"
    },
    "DependencyDelta": {
      "additionalProperties": false,
      "description": "One surviving non-detector dependency difference between environments (contract §3).\n\nAttributes\n----------\npackage : str\n    Canonical distribution name.\nbase_version : str | None\n    Version in the base environment; absent if not installed there.\nhead_version : str | None\n    Version in the head environment; absent if not installed there.",
      "properties": {
        "base_version": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "title": "Base Version"
        },
        "head_version": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "title": "Head Version"
        },
        "package": {
          "title": "Package",
          "type": "string"
        }
      },
      "required": [
        "package",
        "base_version",
        "head_version"
      ],
      "title": "DependencyDelta",
      "type": "object"
    },
    "DiffClass": {
      "description": "Classification of one finding diff (contract §8).\n\nAttributes\n----------\nNEW\n    Present on the head side only.\nDROPPED\n    Present on the base side only.\nCHANGED\n    Present on both sides with at least one observable field changed.",
      "enum": [
        "new",
        "dropped",
        "changed"
      ],
      "title": "DiffClass",
      "type": "string"
    },
    "DiffRollup": {
      "additionalProperties": false,
      "description": "One complete pre-truncation rollup group (reporting contract §3.2).\n\nExactly one of ``rule_id`` and ``kind`` is non-null: a finding with a\nrule ID groups by rule ID regardless of kind; otherwise it groups by\nkind. A ``changed`` pair groups by its reference-side occurrence.\n\nAttributes\n----------\ndiff_class : DiffClass\n    ``new``, ``dropped``, or ``changed``.\nrule_id : str | None\n    Rule ID of the group, when its findings carry one.\nkind : str | None\n    Kind fallback of the group, when its findings carry no rule ID.\ncount : int\n    Number of findings in the group; positive.",
      "properties": {
        "count": {
          "minimum": 1,
          "title": "Count",
          "type": "integer"
        },
        "diff_class": {
          "$ref": "#/$defs/DiffClass"
        },
        "kind": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "title": "Kind"
        },
        "rule_id": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "title": "Rule Id"
        }
      },
      "required": [
        "diff_class",
        "rule_id",
        "kind",
        "count"
      ],
      "title": "DiffRollup",
      "type": "object"
    },
    "DiffTotals": {
      "additionalProperties": false,
      "description": "Diff totals before truncation (contract §8).\n\nAttributes\n----------\nnew : int\n    Count of ``new`` diffs.\ndropped : int\n    Count of ``dropped`` diffs.\nchanged : int\n    Count of ``changed`` diffs.\nchanged_confidence : int\n    ``changed`` diffs whose ``changed_fields`` include confidence.\nchanged_message_only : int\n    ``changed`` diffs whose only changed field is the message.",
      "properties": {
        "changed": {
          "default": 0,
          "title": "Changed",
          "type": "integer"
        },
        "changed_confidence": {
          "default": 0,
          "title": "Changed Confidence",
          "type": "integer"
        },
        "changed_message_only": {
          "default": 0,
          "title": "Changed Message Only",
          "type": "integer"
        },
        "dropped": {
          "default": 0,
          "title": "Dropped",
          "type": "integer"
        },
        "new": {
          "default": 0,
          "title": "New",
          "type": "integer"
        }
      },
      "title": "DiffTotals",
      "type": "object"
    },
    "EnvironmentRecord": {
      "additionalProperties": false,
      "description": "Record of one resolved detector environment (contract §3).\n\nAttributes\n----------\nref : str\n    Detector ref as requested on the CLI.\nsha : str\n    Resolved commit SHA.\nfingerprint : str\n    Full cache fingerprint key of the environment.\nfreeze : tuple[str, ...]\n    Resolved dependency freeze (``name==version`` lines).\nfrom_cache : bool\n    Whether the environment was reused directly from cache.\nrebuilt : bool\n    Whether the environment was rebuilt in this run.",
      "properties": {
        "fingerprint": {
          "title": "Fingerprint",
          "type": "string"
        },
        "freeze": {
          "items": {
            "type": "string"
          },
          "title": "Freeze",
          "type": "array"
        },
        "from_cache": {
          "title": "From Cache",
          "type": "boolean"
        },
        "rebuilt": {
          "title": "Rebuilt",
          "type": "boolean"
        },
        "ref": {
          "title": "Ref",
          "type": "string"
        },
        "sha": {
          "title": "Sha",
          "type": "string"
        }
      },
      "required": [
        "ref",
        "sha",
        "fingerprint",
        "freeze",
        "from_cache",
        "rebuilt"
      ],
      "title": "EnvironmentRecord",
      "type": "object"
    },
    "FetchRecord": {
      "additionalProperties": false,
      "description": "Record of one network fetch performed during the fetch step (contract §3).\n\nAttributes\n----------\nkind : str\n    Fetch kind: ``git`` or ``wheel``.\nname : str\n    Repository URL for ``git`` fetches; distribution filename for ``wheel``.\nresolved : str\n    Resolved commit SHA (``git``) or version (``wheel``).\ndigest : str | None\n    Hex SHA-256 of the fetched artifact, when applicable.",
      "properties": {
        "digest": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Digest"
        },
        "kind": {
          "title": "Kind",
          "type": "string"
        },
        "name": {
          "title": "Name",
          "type": "string"
        },
        "resolved": {
          "title": "Resolved",
          "type": "string"
        }
      },
      "required": [
        "kind",
        "name",
        "resolved"
      ],
      "title": "FetchRecord",
      "type": "object"
    },
    "FindingDiff": {
      "additionalProperties": false,
      "description": "One classified difference between the base and head reports (contract §8).\n\nAttributes\n----------\nschema_version : SchemaVersion\n    Package-wide schema semver (contract §7).\ndiff_class : DiffClass\n    ``new``, ``dropped``, or ``changed``.\nidentity : str\n    Stable identity hash shared by the paired occurrences.\ntool : str\n    Adapter name of the reporting detector.\nproject : str\n    Corpus project name.\npath : str\n    Repo-relative POSIX path of the reported file.\nsymbol : str | None\n    Reported symbol, when the detector names one.\nkind : str\n    Normalized finding kind.\nbase_occurrence : FindingOccurrence | None\n    Base-side occurrence; absent for ``new``.\nhead_occurrence : FindingOccurrence | None\n    Head-side occurrence; absent for ``dropped``.\nchanged_fields : tuple[ChangedField, ...]\n    Fields differing within a ``changed`` pair; empty otherwise.",
      "properties": {
        "base_occurrence": {
          "anyOf": [
            {
              "$ref": "#/$defs/FindingOccurrence"
            },
            {
              "type": "null"
            }
          ],
          "default": null
        },
        "changed_fields": {
          "default": [],
          "items": {
            "$ref": "#/$defs/ChangedField"
          },
          "title": "Changed Fields",
          "type": "array"
        },
        "diff_class": {
          "$ref": "#/$defs/DiffClass"
        },
        "head_occurrence": {
          "anyOf": [
            {
              "$ref": "#/$defs/FindingOccurrence"
            },
            {
              "type": "null"
            }
          ],
          "default": null
        },
        "identity": {
          "title": "Identity",
          "type": "string"
        },
        "kind": {
          "title": "Kind",
          "type": "string"
        },
        "path": {
          "title": "Path",
          "type": "string"
        },
        "project": {
          "title": "Project",
          "type": "string"
        },
        "schema_version": {
          "const": "1.1.0",
          "default": "1.1.0",
          "title": "Schema Version",
          "type": "string"
        },
        "symbol": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "title": "Symbol"
        },
        "tool": {
          "title": "Tool",
          "type": "string"
        }
      },
      "required": [
        "diff_class",
        "identity",
        "tool",
        "project",
        "path",
        "symbol",
        "kind"
      ],
      "title": "FindingDiff",
      "type": "object"
    },
    "FindingOccurrence": {
      "additionalProperties": false,
      "description": "One occurrence of a finding identity in a report (contract §7).\n\nA report holds a multiset of occurrences per identity; the canonical\noccurrence key (contract §8) orders them deterministically.\n\nAttributes\n----------\nschema_version : SchemaVersion\n    Package-wide schema semver (contract §7).\nstart_line : int\n    First line of the reported span (1-based).\nend_line : int\n    Last line of the reported span (1-based, inclusive).\nmessage : str\n    Normalized message text.\nconfidence : int | None\n    Confidence percentage, for tools declaring the capability.\nrule_id : str | None\n    Detector rule ID, when the detector or its documented output\n    category supplies one (reporting contract §3.1).\nraw_excerpt : str | None\n    Untrusted raw detector output for this occurrence; sanitized on render.\nsource_excerpt : SourceExcerpt | None\n    Bounded pinned-source evidence (reporting contract §3.3).",
      "properties": {
        "confidence": {
          "anyOf": [
            {
              "maximum": 100,
              "minimum": 0,
              "type": "integer"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Confidence"
        },
        "end_line": {
          "minimum": 1,
          "title": "End Line",
          "type": "integer"
        },
        "message": {
          "title": "Message",
          "type": "string"
        },
        "raw_excerpt": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Raw Excerpt"
        },
        "rule_id": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Rule Id"
        },
        "schema_version": {
          "const": "1.1.0",
          "default": "1.1.0",
          "title": "Schema Version",
          "type": "string"
        },
        "source_excerpt": {
          "anyOf": [
            {
              "$ref": "#/$defs/SourceExcerpt"
            },
            {
              "type": "null"
            }
          ],
          "default": null
        },
        "start_line": {
          "minimum": 1,
          "title": "Start Line",
          "type": "integer"
        }
      },
      "required": [
        "start_line",
        "end_line",
        "message"
      ],
      "title": "FindingOccurrence",
      "type": "object"
    },
    "ProjectReport": {
      "additionalProperties": false,
      "description": "Per-project slice of the blast radius (contract §8, §9).\n\nAttributes\n----------\nproject : str\n    Corpus project name.\ndiffs : tuple[FindingDiff, ...]\n    Classified diffs, canonically ordered, possibly truncated.\ntotals : DiffTotals\n    Totals before truncation.\nrollups : tuple[DiffRollup, ...]\n    Complete pre-truncation rollups by diff class and rule ID with kind\n    fallback, deterministically ordered (reporting contract §3.2).\ntruncated : bool\n    Whether ``diffs`` was truncated by the results cap.\nbase_findings : int\n    Total base-side findings parsed.\nhead_findings : int\n    Total head-side findings parsed.\nmeasured_cost_seconds : float | None\n    Measured wall-clock analysis cost, when both sides completed.\nerrors : tuple[ToolError, ...]\n    Detector invocation failures for this project.\nintegrity_warnings : tuple[CorpusIntegrityWarning, ...]\n    Expected-clean violations observed on the base side.\nsource_warnings : tuple[str, ...]\n    Bounded warnings from pinned-source evidence collection (reporting\n    contract §3.3).",
      "properties": {
        "base_findings": {
          "title": "Base Findings",
          "type": "integer"
        },
        "diffs": {
          "items": {
            "$ref": "#/$defs/FindingDiff"
          },
          "title": "Diffs",
          "type": "array"
        },
        "errors": {
          "default": [],
          "items": {
            "$ref": "#/$defs/ToolError"
          },
          "title": "Errors",
          "type": "array"
        },
        "head_findings": {
          "title": "Head Findings",
          "type": "integer"
        },
        "integrity_warnings": {
          "default": [],
          "items": {
            "$ref": "#/$defs/CorpusIntegrityWarning"
          },
          "title": "Integrity Warnings",
          "type": "array"
        },
        "measured_cost_seconds": {
          "anyOf": [
            {
              "type": "number"
            },
            {
              "type": "null"
            }
          ],
          "title": "Measured Cost Seconds"
        },
        "project": {
          "title": "Project",
          "type": "string"
        },
        "rollups": {
          "default": [],
          "items": {
            "$ref": "#/$defs/DiffRollup"
          },
          "title": "Rollups",
          "type": "array"
        },
        "source_warnings": {
          "default": [],
          "items": {
            "type": "string"
          },
          "title": "Source Warnings",
          "type": "array"
        },
        "totals": {
          "$ref": "#/$defs/DiffTotals"
        },
        "truncated": {
          "title": "Truncated",
          "type": "boolean"
        }
      },
      "required": [
        "project",
        "diffs",
        "totals",
        "truncated",
        "base_findings",
        "head_findings",
        "measured_cost_seconds"
      ],
      "title": "ProjectReport",
      "type": "object"
    },
    "RunManifest": {
      "additionalProperties": false,
      "description": "Record of resolved refs, versions, environments, and settings for one run (contract §2).\n\nAttributes\n----------\nschema_version : SchemaVersion\n    Package-wide schema semver (contract §7).\ncreated_at : datetime\n    UTC timestamp of manifest assembly.\ntool : str\n    Adapter name of the detector under test.\ndetector_repo : str | None\n    Detector repository URL; absent for escape-hatch runs.\nbase : EnvironmentRecord | None\n    Base-side environment; absent for escape-hatch runs.\nhead : EnvironmentRecord | None\n    Head-side environment; absent for escape-hatch runs.\nbase_cmd : tuple[str, ...] | None\n    Escape-hatch base command (``--old-cmd``), if used.\nhead_cmd : tuple[str, ...] | None\n    Escape-hatch head command (``--new-cmd``), if used.\ncomparable : bool\n    False only for unmanaged escape-hatch runs (contract §3).\nenvironment_delta : tuple[DependencyDelta, ...]\n    Non-detector dependency differences surviving paired resolution.\nisolation_enforced : bool\n    Whether build/analysis sandboxing was enforced (contract §11).\nplatform : str\n    Platform tag of the run host.\npython_version : str\n    Python version running the detectors.\ninstaller : str | None\n    Installer name and version used to build environments.\nfetches : tuple[FetchRecord, ...]\n    Every fetch performed during the fetch step.\ncorpus_pins : tuple[CorpusPinRecord, ...]\n    Resolved corpus pins for the run.\nsettings : RunSettings\n    Effective run settings.",
      "properties": {
        "base": {
          "anyOf": [
            {
              "$ref": "#/$defs/EnvironmentRecord"
            },
            {
              "type": "null"
            }
          ]
        },
        "base_cmd": {
          "anyOf": [
            {
              "items": {
                "type": "string"
              },
              "type": "array"
            },
            {
              "type": "null"
            }
          ],
          "title": "Base Cmd"
        },
        "comparable": {
          "title": "Comparable",
          "type": "boolean"
        },
        "corpus_pins": {
          "items": {
            "$ref": "#/$defs/CorpusPinRecord"
          },
          "title": "Corpus Pins",
          "type": "array"
        },
        "created_at": {
          "format": "date-time",
          "title": "Created At",
          "type": "string"
        },
        "detector_repo": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "title": "Detector Repo"
        },
        "environment_delta": {
          "items": {
            "$ref": "#/$defs/DependencyDelta"
          },
          "title": "Environment Delta",
          "type": "array"
        },
        "fetches": {
          "items": {
            "$ref": "#/$defs/FetchRecord"
          },
          "title": "Fetches",
          "type": "array"
        },
        "head": {
          "anyOf": [
            {
              "$ref": "#/$defs/EnvironmentRecord"
            },
            {
              "type": "null"
            }
          ]
        },
        "head_cmd": {
          "anyOf": [
            {
              "items": {
                "type": "string"
              },
              "type": "array"
            },
            {
              "type": "null"
            }
          ],
          "title": "Head Cmd"
        },
        "installer": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "title": "Installer"
        },
        "isolation_enforced": {
          "title": "Isolation Enforced",
          "type": "boolean"
        },
        "platform": {
          "title": "Platform",
          "type": "string"
        },
        "python_version": {
          "title": "Python Version",
          "type": "string"
        },
        "schema_version": {
          "const": "1.1.0",
          "default": "1.1.0",
          "title": "Schema Version",
          "type": "string"
        },
        "settings": {
          "$ref": "#/$defs/RunSettings"
        },
        "tool": {
          "title": "Tool",
          "type": "string"
        }
      },
      "required": [
        "created_at",
        "tool",
        "detector_repo",
        "base",
        "head",
        "base_cmd",
        "head_cmd",
        "comparable",
        "environment_delta",
        "isolation_enforced",
        "platform",
        "python_version",
        "installer",
        "fetches",
        "corpus_pins",
        "settings"
      ],
      "title": "RunManifest",
      "type": "object"
    },
    "RunSettings": {
      "additionalProperties": false,
      "description": "Effective settings of one run, recorded for reproducibility (contract §3).\n\nAttributes\n----------\njobs : int\n    Maximum concurrent per-project subprocesses.\ntimeout : float\n    Default per-(project, tool) timeout in seconds.\nmax_results : int\n    Cap on rendered finding diffs.\nexcerpt_lines : int\n    Pinned-source evidence lines stored and rendered per occurrence;\n    ``0`` disables source excerpts (reporting contract §3.3).\nfail_on : tuple[str, ...]\n    Enabled ``--fail-on`` gates.\nselection : tuple[str, ...]\n    Selected corpus project names, in run order.",
      "properties": {
        "excerpt_lines": {
          "title": "Excerpt Lines",
          "type": "integer"
        },
        "fail_on": {
          "items": {
            "type": "string"
          },
          "title": "Fail On",
          "type": "array"
        },
        "jobs": {
          "title": "Jobs",
          "type": "integer"
        },
        "max_results": {
          "title": "Max Results",
          "type": "integer"
        },
        "selection": {
          "items": {
            "type": "string"
          },
          "title": "Selection",
          "type": "array"
        },
        "timeout": {
          "title": "Timeout",
          "type": "number"
        }
      },
      "required": [
        "jobs",
        "timeout",
        "max_results",
        "excerpt_lines",
        "fail_on",
        "selection"
      ],
      "title": "RunSettings",
      "type": "object"
    },
    "SourceExcerpt": {
      "additionalProperties": false,
      "description": "Bounded pinned-source evidence for one occurrence (reporting contract §3.3).\n\nThe excerpt is derived review context read from the byte-identical\npinned corpus checkout; it never participates in finding identity, the\ncanonical occurrence key, or changed-field classification.\n\nAttributes\n----------\nstart_line : int\n    Line number of the first retained line (1-based); always the\n    occurrence's reported ``start_line``.\nlines : tuple[str, ...]\n    Retained consecutive source lines, starting at ``start_line``.\nomitted_lines : int\n    Existing reported-span lines dropped by the evidence budget.",
      "properties": {
        "lines": {
          "items": {
            "type": "string"
          },
          "minItems": 1,
          "title": "Lines",
          "type": "array"
        },
        "omitted_lines": {
          "default": 0,
          "minimum": 0,
          "title": "Omitted Lines",
          "type": "integer"
        },
        "start_line": {
          "minimum": 1,
          "title": "Start Line",
          "type": "integer"
        }
      },
      "required": [
        "start_line",
        "lines"
      ],
      "title": "SourceExcerpt",
      "type": "object"
    },
    "ToolError": {
      "additionalProperties": false,
      "description": "Failure of one detector invocation on one project side (contract §9).\n\nAttributes\n----------\nside : str\n    ``base`` or ``head``.\nexit_code : int | None\n    Subprocess exit code; absent when the invocation timed out.\ndetail : str\n    Sanitized description of the failure.",
      "properties": {
        "detail": {
          "title": "Detail",
          "type": "string"
        },
        "exit_code": {
          "anyOf": [
            {
              "type": "integer"
            },
            {
              "type": "null"
            }
          ],
          "title": "Exit Code"
        },
        "side": {
          "title": "Side",
          "type": "string"
        }
      },
      "required": [
        "side",
        "exit_code",
        "detail"
      ],
      "title": "ToolError",
      "type": "object"
    }
  },
  "additionalProperties": false,
  "description": "The blast radius: all finding diffs plus summary totals (contract §2, §9).\n\nAttributes\n----------\nschema_version : SchemaVersion\n    Package-wide schema semver (contract §7).\nmanifest : RunManifest\n    Run manifest for reproducibility.\nprojects : tuple[ProjectReport, ...]\n    Per-project reports, in run order.\ntotals : DiffTotals\n    Overall totals before truncation.\nrollups : tuple[DiffRollup, ...]\n    Overall rollups: the sum of the complete project rollups,\n    deterministically ordered (reporting contract §3.2).\ntruncated : bool\n    Whether any project's diffs were truncated.",
  "properties": {
    "manifest": {
      "$ref": "#/$defs/RunManifest"
    },
    "projects": {
      "items": {
        "$ref": "#/$defs/ProjectReport"
      },
      "title": "Projects",
      "type": "array"
    },
    "rollups": {
      "default": [],
      "items": {
        "$ref": "#/$defs/DiffRollup"
      },
      "title": "Rollups",
      "type": "array"
    },
    "schema_version": {
      "const": "1.1.0",
      "default": "1.1.0",
      "title": "Schema Version",
      "type": "string"
    },
    "totals": {
      "$ref": "#/$defs/DiffTotals"
    },
    "truncated": {
      "title": "Truncated",
      "type": "boolean"
    }
  },
  "required": [
    "manifest",
    "projects",
    "totals",
    "truncated"
  ],
  "title": "Report",
  "type": "object"
};

export const REVIEW_SESSION_SCHEMA = {
  "$defs": {
    "FindingLocator": {
      "additionalProperties": false,
      "description": "Persistent reference to one finding diff in one report (contract §7, explorer §6.2).\n\n``line`` addresses the diff class's reference-side start line — head for\n``new``, base for ``dropped`` and ``changed``. ``occurrence`` is the\nzero-based position of the diff within the subsequence of its serialized\nper-project diff sequence sharing ``(identity, line)``, in serialized\norder.\n\nAttributes\n----------\nproject : str\n    Corpus project name.\nidentity : str\n    Stable finding identity hash.\nline : int\n    Reference-side start line (1-based).\noccurrence : int\n    Zero-based index among diffs sharing ``(identity, line)``.",
      "properties": {
        "identity": {
          "title": "Identity",
          "type": "string"
        },
        "line": {
          "minimum": 1,
          "title": "Line",
          "type": "integer"
        },
        "occurrence": {
          "minimum": 0,
          "title": "Occurrence",
          "type": "integer"
        },
        "project": {
          "title": "Project",
          "type": "string"
        }
      },
      "required": [
        "project",
        "identity",
        "line",
        "occurrence"
      ],
      "title": "FindingLocator",
      "type": "object"
    },
    "ReviewDisposition": {
      "description": "Reviewer judgment about one displayed finding diff (explorer contract §10.1).\n\nDispositions concern the expected blast radius of a detector change;\nthey are not the internal-corpus annotation verdicts and are never\nstored in or translated into :class:`Annotation`.\n\nAttributes\n----------\nEXPECTED\n    The reviewer believes this diff belongs in the intended blast radius.\nUNEXPECTED\n    The reviewer believes this diff warrants attention in the detector PR.",
      "enum": [
        "expected",
        "unexpected"
      ],
      "title": "ReviewDisposition",
      "type": "string"
    },
    "ReviewEntry": {
      "additionalProperties": false,
      "description": "One reviewed finding in a review session (explorer contract §11.1).\n\nAttributes\n----------\nlocator : FindingLocator\n    Locator of the reviewed finding diff.\ndisposition : ReviewDisposition\n    ``expected`` or ``unexpected``.\nnote : str | None\n    Optional reviewer note of at most 4,096 Unicode code points.",
      "properties": {
        "disposition": {
          "$ref": "#/$defs/ReviewDisposition"
        },
        "locator": {
          "$ref": "#/$defs/FindingLocator"
        },
        "note": {
          "anyOf": [
            {
              "maxLength": 4096,
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "title": "Note"
        }
      },
      "required": [
        "locator",
        "disposition"
      ],
      "title": "ReviewEntry",
      "type": "object"
    }
  },
  "additionalProperties": false,
  "description": "Portable review state for one exact report byte representation (explorer §11.1).\n\n``report_sha256`` is the SHA-256 digest of the exact imported report\nbytes; semantically equivalent but byte-different reports intentionally\nhave different digests. Unreviewed findings are omitted.\n\nAttributes\n----------\nschema_version : SchemaVersion\n    Package-wide schema semver (contract §7).\nreport_sha256 : str\n    Lowercase hex SHA-256 digest of the exact report bytes.\nreport_schema_version : str\n    Schema version declared by the reviewed report.\ncreated_at : datetime\n    UTC time the session was first created for the report digest.\nupdated_at : datetime\n    UTC time a portable entry last changed.\nentries : tuple[ReviewEntry, ...]\n    Review entries with unique locators, in canonical report order.",
  "properties": {
    "created_at": {
      "format": "date-time",
      "title": "Created At",
      "type": "string"
    },
    "entries": {
      "items": {
        "$ref": "#/$defs/ReviewEntry"
      },
      "title": "Entries",
      "type": "array"
    },
    "report_schema_version": {
      "title": "Report Schema Version",
      "type": "string"
    },
    "report_sha256": {
      "pattern": "^[0-9a-f]{64}$",
      "title": "Report Sha256",
      "type": "string"
    },
    "schema_version": {
      "const": "1.1.0",
      "default": "1.1.0",
      "title": "Schema Version",
      "type": "string"
    },
    "updated_at": {
      "format": "date-time",
      "title": "Updated At",
      "type": "string"
    }
  },
  "required": [
    "report_sha256",
    "report_schema_version",
    "created_at",
    "updated_at",
    "entries"
  ],
  "title": "ReviewSession",
  "type": "object"
};

export const SUPPORTED_REPORT_SCHEMA_VERSIONS = ["1.1.0"];
