# Vendored OPC Foundation encoding vectors

These are golden test vectors copied verbatim from the OPC UA .NET Standard reference stack, used as
an independent cross-stack oracle for async-opcua's encoders (see `src/tests/conformance_vectors.rs`).

- **Source repo:** https://github.com/OPCFoundation/UA-.NETStandard
- **Commit:** `147c287b8c8d9f6fee7275c5ea1e2be19c961d79`
- **Path in source:** `Fuzzing/Opc.Ua.Encoders.Fuzz.Corpus/Testcases.BuiltInTypes/Binary/`
- **License:** OPC Foundation MIT License 1.00 (http://opcfoundation.org/License/MIT/1.00/) — the
  whole repo, including its fuzz corpus, is MIT; redistribution and modification are permitted with
  the notice retained.

`builtin_binary/*.bin` — each file is a bare OPC UA Binary encoding (Part 6 §5.2) of a single
Built-in type: `nodeid`, `expandednodeid`, `qualifiedname`, `localizedtext`, `variant`, `datavalue`,
`diagnosticinfo`, `extensionobject`.
