# Data Model: StatusCode Conformance Test Matrix

## ImplementedStandardSection

Represents one implemented OPC UA standard section.

Fields:

- `part`: OPC UA document identifier, such as `OPC-10000-4`.
- `section`: Section number or annex reference.
- `title`: Standard section title when known.
- `implemented_area`: Repository crate/module that implements the behavior.
- `source`: `mcp`, `repo-audit`, or `feature-spec`.

Validation rules:

- Must refer to behavior implemented in the repository.
- Must not represent an unimplemented future feature.

## StatusCodePath

Represents one happy or negative behavior path to test or classify.

Fields:

- `id`: Stable matrix row ID, such as `P4-SVC-001`.
- `standard_section`: Link to an ImplementedStandardSection.
- `status_or_result`: Exact StatusCode or happy-path result.
- `behavior`: The invalid input or successful operation being exercised.
- `implementation_area`: Production file or module family.
- `test_target`: Planned or existing test file.
- `classification`: CoverageClassification.
- `task_id`: Optional task ID when classification is `tasked`.

Validation rules:

- `task_id` is required only for `tasked` rows.
- `status_or_result` must be exact for negative paths.
- Environmental paths must name why they are not deterministic.

## CoverageClassification

Allowed values:

- `covered`: Existing tests already assert the relevant behavior.
- `tasked`: A task will add exactly one test function.
- `environmental`: Deterministic local testing is not available without injection infrastructure.
- `generated-only`: The StatusCode appears only as a generated constant or metadata.
- `unimplemented`: The standard surface is not implemented and belongs in the conformance backlog.

## TestTask

Represents one implementation task.

Fields:

- `task_id`: Sequential task ID from `tasks.md`.
- `story`: User story label.
- `test_name`: Exact test function to add.
- `test_file`: Exact file path.
- `matrix_row`: StatusCodePath ID.
- `spec_reference`: OPC UA Part and section.

Validation rules:

- Must add exactly one test function.
- Must not introduce a second test helper that is itself marked `#[test]` or `#[tokio::test]`.
- May include minimal production changes only when needed to satisfy that one test.
