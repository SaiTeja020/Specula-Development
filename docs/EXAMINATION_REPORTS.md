# Court and technical examination reports

The Report tab provides audience-specific PDF downloads and previews generated
with ReportLab. Select the report type, then preview or download it. Saved cases
use their stored evidence; the original report remains available for reference.
PDF delivery retains backend authorization and final-report completion checks.

The **Court submission report** summarizes scope, acquisition and custody,
supported observations, cited exhibits and limitations. Examiner and reviewer
approval remains unsigned and requires qualified review before submission.

The **Technical report** details telemetry coverage, cited detections, event
records, execution provenance and analyst follow-up. Model assessments remain
analysis rather than source evidence. Missing findings do not establish a clean host.

Both formats distinguish evidence from assessments, disclose synthetic input
where applicable and retain uncertainty. Report styling does not establish
admissibility, expert approval, verified custody or forensic completeness.
Document generation time is separate from investigation time.

ReportLab is pinned in the shared API image and checked by rendering a PDF during
image construction. See [local build and validation](local_validation.md) for the
build command; recreate the API services after rebuilding dependency changes.
