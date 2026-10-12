# Court and technical examination reports

The Report tab offers two separate downloadable standalone HTML documents. Open
the printable document and use the browser's Print → Save as PDF to produce a PDF.
Both documents use formal A4 print styling, numbered sections and exhibit indices.
The download displays the SHA-256 of the exact HTML document.

The **Court submission report** includes scope, declared examiner/authority,
receipt and file inventory hashes, custody limitations, reproducible component
fingerprints, evidence-cited findings, event exhibits, a Rule 702/Daubert review
table and unsigned examiner/reviewer approval fields. Its status is a submission
draft requiring review. It does not generate signatures, court seals or a claim
of admissibility.

The **Technical cyber-team report** includes telemetry/class coverage, ingestion
filters and diagnostics, triage, guardrail/review results, complete saved agent
outputs, attribution/timeline state, normalized evidence and actionable review
steps. Model analysis is identified as unverified unless supported by checked
evidence. An absent finding or missing attack path does not establish a clean host.

New report-generation runs save both documents in the durable checkpoint. Older
cases can obtain the new formats from their saved evidence without rerunning
agents; the original historical report remains available in the Report tab.
Document generation time is recorded separately from investigation start time.

Admissibility depends on the actual expert, evidence, methodology, reliable
application and the court's assessment. The current system has no validated
complete-system error rate, independent peer-review record or laboratory
accreditation sufficient to assert it passes those criteria. These gaps are
reported, not replaced by report styling. Manifest statements are declarations,
not verified credentials or custody transfers.

Primary reference: [Federal Rules of Evidence, Rule 702, December 1, 2025](https://www.uscourts.gov/sites/default/files/document/federal-rules-of-evidence.pdf).
Daubert considerations include testability, peer review/publication, known or
potential error rates and standards, and general acceptance; see the
[U.S. Court of Appeals for the Armed Forces discussion of Daubert](https://www.armfor.uscourts.gov/digest/IIIC8.htm).
