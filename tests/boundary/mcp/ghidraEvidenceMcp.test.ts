import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import { describe, expect, it } from "vitest";
import { EnhancedTools } from "../../../src/application/EnhancedTools.js";
import { connectGhidraMcp, sessionEvidence } from "./ghidraMcpHarness.js";
import { functionDossierSchema } from "../../../src/domain/native/functionDossier.js";
import { functionComparisonResultSchema } from "../../../src/domain/functionComparisonSchemas.js";
import {
  ghidraFunctionDossier,
  ghidraFunctionIdentity,
} from "../../../src/domain/ghidraValues.fixture.js";
import {
  jsonObjectSchema,
  jsonValueSchema,
  type JsonValue,
} from "../../../src/domain/jsonValue.js";
import { ok } from "../../../src/domain/result.js";
import {
  isGhidraFunctionOperation,
  type GhidraFunctionOperation,
} from "../../../src/ghidra/GhidraFunctionValues.js";

it.each([
  { pseudocodeAvailable: true, reportsCoverage: true },
  { pseudocodeAvailable: false, reportsCoverage: true },
  { pseudocodeAvailable: true, reportsCoverage: false },
  { pseudocodeAvailable: false, reportsCoverage: false },
])(
  "compares observed empty Ghidra facets with pseudocode=$pseudocodeAvailable and coverage=$reportsCoverage",
  async ({ pseudocodeAvailable, reportsCoverage }) => {
    const coverage = reportsCoverage
      ? { status: "complete" as const }
      : undefined;
    const dossier = functionDossierSchema.parse(ghidraFunctionDossier());
    Object.assign(dossier, {
      comments: [],
      callers: [],
      callees: [],
      incoming_references: [],
      outgoing_references: [],
      referenced_strings: [],
      referenced_names: [],
      pseudocode: pseudocodeAvailable ? dossier.pseudocode : "",
      facet_availability: {
        pseudocode: pseudocodeAvailable
          ? { available: true }
          : { available: false, reason: "Ghidra did not supply pseudocode." },
        assembly: { available: true },
        comments: { available: true },
        callers: { available: true },
        callees: { available: true },
        references: { available: true },
        strings_names: { available: true },
        cfg: { available: true },
      },
    });
    const harness = await connectGhidraMcp(
      "ghidra-empty-dossier-coverage",
      (operation) => {
        if (operation !== "analyze_function")
          throw new Error(`Unexpected operation: ${operation}`);
        return Promise.resolve(
          ok({
            value: jsonValueSchema.parse(dossier),
            limitations: [],
            ...(coverage === undefined
              ? {}
              : { relationship_coverage: coverage }),
          }),
        );
      },
    );
    try {
      const analyzed = await harness.mcp.callTool({
        name: "analyze_function",
        arguments: { procedure: dossier.procedure.address, detail: "complete" },
      });
      expect(analyzed.isError).not.toBe(true);
      const evidence = sessionEvidence(
        harness.session,
        analyzed.structuredContent,
      );
      expect(evidence.relationship_coverage).toEqual(coverage ?? null);
      expect(evidence.normalized_result).toEqual(dossier);
      const reply = await harness.mcp.callTool({
        name: "compare_functions",
        arguments: { left: evidence, right: evidence },
      });
      expect(reply.isError, JSON.stringify(reply)).not.toBe(true);
      const comparison = functionComparisonResultSchema.parse(
        sessionEvidence(harness.session, reply.structuredContent)
          .normalized_result,
      );
      expect(
        Object.fromEntries(
          comparison.dimensions.map(({ dimension, status }) => [
            dimension,
            status,
          ]),
        ),
      ).toEqual({
        identity: "unchanged",
        pseudocode: pseudocodeAvailable ? "unchanged" : "unknown",
        assembly: "unchanged",
        comments: "unchanged",
        calls: reportsCoverage ? "unchanged" : "unknown",
        references: "unchanged",
        strings_names: "unchanged",
        cfg: "unchanged",
      });
      const replay = await harness.session.execute(
        "analyze_function",
        evidence.parameters,
      );
      if (!replay.ok) throw replay.error;
      expect(replay.value.relationshipCoverage).toEqual(coverage);
      expect(harness.calls).toEqual(["analyze_function"]);
    } finally {
      await harness.close();
    }
  },
);

it("retains terminal-call qualifications across function views and snapshot replay", async () => {
  const limitation =
    "Ghidra Listing reports a terminal call at 0x401000 to EXTERNAL:0x20 __tls_get_addr (external=true, thunk=false, hasNoReturn=true); fallthrough is excluded by Ghidra's flow model. This records Ghidra's FunctionManager flag, not an independent verification that the callee cannot return.";
  const dossier = functionDossierSchema.parse(ghidraFunctionDossier());
  dossier.limitations.push(limitation);
  const { signature, locals, ...identity } = dossier.procedure;
  if (!identity.body.available)
    throw new Error("The function fixture must include its analyzed body");
  const values = new Map<GhidraFunctionOperation, JsonValue>([
    ["procedure_pseudo_code", dossier.pseudocode],
    ["procedure_assembly", dossier.assembly.join("\n")],
    [
      "procedure_info",
      {
        name: identity.name,
        entrypoint: identity.address,
        signature,
        locals,
        basicblock_count: dossier.basic_blocks.length,
        length: identity.body.total_bytes,
        classification: identity.classification,
        body: identity.body,
      },
    ],
    [
      "read_function_instructions",
      {
        procedure: identity,
        instructions: dossier.assembly,
        limitations: [limitation],
      },
    ],
    ["procedure_callees", ["0x402000"]],
    ["procedure_callers", [identity.address]],
    ["analyze_function", jsonValueSchema.parse(dossier)],
  ]);
  const harness = await connectGhidraMcp(
    "ghidra-terminal-call-evidence",
    (operation) => {
      if (!isGhidraFunctionOperation(operation))
        throw new Error(`Unexpected operation: ${operation}`);
      const value = values.get(operation);
      if (value === undefined)
        throw new Error(`Unexpected operation: ${operation}`);
      return Promise.resolve(ok({ value, limitations: [limitation] }));
    },
  );
  try {
    for (const [name, value] of values) {
      const request = {
        name,
        arguments:
          name === "analyze_function"
            ? { procedure: identity.address, detail: "complete" }
            : { procedure: identity.address, document: "fixture" },
      };
      const reply = await harness.mcp.callTool(request);
      expect(reply.isError, `${name}: ${JSON.stringify(reply)}`).not.toBe(true);
      const evidence = sessionEvidence(
        harness.session,
        reply.structuredContent,
      );
      expect(evidence.normalized_result, name).toEqual(value);
      expect(evidence.raw_result, name).toBeNull();
      expect(evidence.limitations, name).toContain(limitation);
      expect(evidence.analysis_profile?.parameters).toMatchObject({
        function_boundary_observations:
          "ghidra-function-boundary-limitations-v4",
      });
      const replay = await harness.session.execute(name, evidence.parameters);
      if (!replay.ok) throw replay.error;
      expect(replay.value.result, name).toEqual(value);
      expect(replay.value.limitations, name).toContain(limitation);
      expect(replay.value.limitations, name).toContainEqual(
        expect.stringContaining("Loaded from a local REA analysis snapshot"),
      );
    }
    expect(harness.calls).toEqual([...values.keys()]);
  } finally {
    await harness.close();
  }
});

it("retains handler-region limitations on incoming and outgoing reference Evidence", async () => {
  const limitation =
    "Ghidra Listing shows a Borland/Delphi-style SEH frame registration at 0x40108f (push 0x4010c0 followed by fs-segment stack chaining); handler 0x4010c0 lies outside this procedure's body, so callees, strings, and cross-references may omit the handler region.";
  const dossier = functionDossierSchema.parse(ghidraFunctionDossier());
  const harness = await connectGhidraMcp(
    "ghidra-seh-reference-evidence",
    (operation, input) => {
      if (operation !== "procedure_references")
        throw new Error(`Unexpected operation: ${operation}`);
      return Promise.resolve(
        ok({
          value: jsonValueSchema.parse({
            procedure: ghidraFunctionIdentity(),
            direction: input.direction ?? "outgoing",
            references: [],
            reference_kinds_available: true,
            unresolved_calls: [],
          }),
          limitations: [limitation],
        }),
      );
    },
  );
  try {
    for (const direction of ["incoming", "outgoing"] as const) {
      const reply = await harness.mcp.callTool({
        name: "procedure_references",
        arguments: { procedure: dossier.procedure.address, direction },
      });
      expect(reply.isError, JSON.stringify(reply)).not.toBe(true);
      const evidence = sessionEvidence(
        harness.session,
        reply.structuredContent,
      );
      expect(evidence.normalized_result).toMatchObject({ direction });
      expect(evidence.raw_result).toBeNull();
      expect(evidence.limitations).toContain(limitation);
      const replay = await harness.session.execute(
        "procedure_references",
        evidence.parameters,
      );
      if (!replay.ok) throw replay.error;
      expect(replay.value.limitations).toContain(limitation);
    }
    expect(harness.calls).toEqual([
      "procedure_references",
      "procedure_references",
      "procedure_references",
      "procedure_references",
    ]);
  } finally {
    await harness.close();
  }
});

it("rejects contradictory annotation readback across the provider and MCP boundaries", async () => {
  const dossier = functionDossierSchema.parse(ghidraFunctionDossier());
  const annotations = {
    address: dossier.procedure.address,
    name: dossier.procedure.name,
    comment: null,
    inline_comment: "Finding",
  };
  const effects = {
    scope: "session-analysis-database",
    source_bytes_modified: false,
    persists_after_close: false,
  };
  const original = { annotations, dossier, effects };
  let output = jsonValueSchema.parse(original);
  const harness = await connectGhidraMcp("ghidra-malformed-annotation", () =>
    Promise.resolve(ok(output)),
  );
  try {
    const accepted = await harness.mcp.callTool({
      name: "annotate_native_function",
      arguments: {
        procedure: annotations.address,
        inline_comment: "Finding",
      },
    });
    expect(accepted.isError).not.toBe(true);
    expect(accepted.structuredContent).toMatchObject({
      normalized_result: { annotations },
    });
    for (const value of [
      { ...original, annotations: { ...annotations, name: "different" } },
      { ...original, annotations: { ...annotations, address: "0x9999" } },
      { ...original, effects: { ...effects, source_bytes_modified: true } },
      { ...original, effects: { ...effects, persists_after_close: true } },
      { ...original, dossier: { ...dossier, native_value_flow: null } },
    ]) {
      output = jsonValueSchema.parse(value);
      const reply = await harness.mcp.callTool({
        name: "annotate_native_function",
        arguments: {
          procedure: annotations.address,
          inline_comment: "Finding",
        },
      });
      expect(reply.isError).toBe(true);
      expect(parseMcpToolError(reply)).toMatchObject({
        error: { code: "unreadable_output" },
      });
    }
  } finally {
    await harness.close();
  }
});

/** Connect a Ghidra MCP session whose bridge returns the current `output`. */
const connectNamingMcp = async (name: string) => {
  const requests: Readonly<Record<string, JsonValue>>[] = [];
  const bridge = { output: null as unknown };
  const harness = await connectGhidraMcp(name, (_operation, input) => {
    requests.push(input);
    return Promise.resolve(ok(jsonValueSchema.parse(bridge.output)));
  });
  const { tools } = await harness.mcp.listTools();
  // Validate every reply against the advertised named output schema.
  const call = (tool: string, arguments_: Record<string, unknown>) => {
    const toolDefinition = tools.find((item) => item.name === tool);
    if (toolDefinition === undefined) throw new Error(`Missing ${tool}`);
    return harness.mcp.callTool(
      { name: tool, arguments: arguments_ },
      { toolDefinition },
    );
  };
  return { harness, requests, bridge, call };
};

const heldFailure = {
  address: "0x1000",
  reason: "name_held_by_unselected_address",
  related_addresses: ["0x3000"],
};
const duplicateFailure = {
  address: "0x1000",
  reason: "duplicate_requested_name",
  related_addresses: ["0x2000"],
};

it("routes address naming to Ghidra with compact results and retained failure reasons", async () => {
  const { harness, requests, bridge, call } = await connectNamingMcp(
    "ghidra-address-naming",
  );
  try {
    bridge.output = { applied: true, failure: null };
    const single = await call("set_address_name", {
      address: "0x1000",
      name: "fixture_entry",
    });
    expect(single.isError).not.toBe(true);
    expect(single.structuredContent).toMatchObject({
      normalized_result: true,
      raw_result: null,
    });
    bridge.output = { applied: false, failure: heldFailure };
    const taken = await call("set_address_name", {
      address: "0x1000",
      name: "g_taken",
    });
    expect(taken.isError).not.toBe(true);
    expect(taken.structuredContent).toMatchObject({
      normalized_result: false,
      raw_result: bridge.output,
    });

    // Bridge reply for three competing requests, a dependent request, the
    // independent rename of the address holding its name before the batch,
    // and an address space the target does not define.
    const competing = (address: string, ...others: string[]) => ({
      address,
      reason: "duplicate_requested_name",
      related_addresses: others,
    });
    const decided = {
      results: {
        "0x1000": false,
        "0x2000": false,
        "0x3000": false,
        "0x4000": true,
        "0x5000": false,
        "nospace:0x10": false,
      },
      failures: {
        "0x1000": competing("0x1000", "0x2000", "0x3000"),
        "0x2000": competing("0x2000", "0x1000", "0x3000"),
        "0x3000": competing("0x3000", "0x1000", "0x2000"),
        "0x5000": {
          address: "0x5000",
          reason: "name_held_by_selected_address",
          related_addresses: ["0x4000"],
        },
        "nospace:0x10": {
          address: null,
          reason: "invalid_address",
          related_addresses: [],
        },
      },
    };
    bridge.output = decided;
    const names = {
      "0x1000": "g_shared",
      "0x2000": "g_shared",
      "0x3000": "g_shared",
      "0x4000": "g_moved",
      "0x5000": "g_held_by_4000",
      "nospace:0x10": "g_unknown_space",
    };
    const reversed = Object.fromEntries(Object.entries(names).reverse());
    const batches = [];
    for (const ordered of [names, reversed]) {
      const reply = await call("set_addresses_names", { names: ordered });
      expect(reply.isError).not.toBe(true);
      batches.push(sessionEvidence(harness.session, reply.structuredContent));
    }
    for (const evidence of batches) {
      expect(evidence.normalized_result).toEqual(decided.results);
      expect(evidence.raw_result).toEqual(decided);
      expect(evidence.parameters).toEqual({ names });
    }
    // Equal canonical parameters and outcomes give one Evidence identity.
    expect(batches[1]!.evidence_id).toBe(batches[0]!.evidence_id);
    // The bridge still receives the caller's member order; it is not a choice.
    expect(
      requests
        .slice(2, 4)
        .map((input) => Object.keys(jsonObjectSchema.parse(input.names))),
    ).toEqual([Object.keys(names), Object.keys(reversed)]);

    bridge.output = { results: { "0x1000": true }, failures: {} };
    const applied = await call("set_addresses_names", {
      names: { "0x1000": "fixture_entry" },
    });
    expect(applied.isError).not.toBe(true);
    expect(applied.structuredContent).toMatchObject({
      normalized_result: { "0x1000": true },
      raw_result: null,
    });
    const dispatched = requests.length;
    const empty = await harness.mcp.callTool({
      name: "set_addresses_names",
      arguments: { names: {} },
    });
    expect(empty.isError).toBe(true);
    expect(requests).toHaveLength(dispatched);
  } finally {
    await harness.close();
  }
});

it("rejects Ghidra naming replies whose outcomes and reasons disagree", async () => {
  const { harness, requests, bridge, call } = await connectNamingMcp(
    "ghidra-malformed-naming",
  );
  const batch = (
    results: Record<string, boolean>,
    failures: Record<string, unknown>,
  ) => ["set_addresses_names", { results, failures }] as const;
  const cases = [
    ["set_address_name", true],
    ["set_address_name", { applied: true, failure: heldFailure }],
    ["set_address_name", { applied: false, failure: null }],
    ["set_address_name", { applied: false, failure: duplicateFailure }],
    ["set_addresses_names", { "0x1000": false }],
    batch({ "0x1000": false, "0x2000": true }, {}),
    batch(
      { "0x1000": false },
      { "0x1000": { ...duplicateFailure, related_addresses: [] } },
    ),
    batch(
      { "0x1000": false },
      { "0x1000": { ...duplicateFailure, related_addresses: ["0x1000"] } },
    ),
    batch(
      { "0x1000": false },
      { "0x1000": duplicateFailure, "0x2000": duplicateFailure },
    ),
  ] as const;
  try {
    for (const [tool, malformed] of cases) {
      bridge.output = malformed;
      const reply = await call(
        tool,
        tool === "set_address_name"
          ? { address: "0x1000", name: "fixture_entry" }
          : { names: { "0x1000": "fixture_entry" } },
      );
      expect(reply.isError, JSON.stringify(malformed)).toBe(true);
      expect(parseMcpToolError(reply)).toMatchObject({
        error: { code: "unreadable_output" },
      });
    }
    expect(requests).toHaveLength(cases.length);
  } finally {
    await harness.close();
  }
});

describe("Ghidra MCP evidence parity", () => {
  it("preserves provider evidence, composed parity, and capability routing", async () => {
    const harness = await connectGhidraMcp("ghidra-parity");
    const { mcp, session } = harness;
    try {
      const listed = sessionEvidence(
        session,
        (
          await mcp.callTool({
            name: "list_procedures",
            arguments: {},
          })
        ).structuredContent,
      );
      expect(listed).toMatchObject({
        operation: "list_procedures",
        provider: { id: "ghidra", name: "Ghidra", version: "12.1.4" },
        analysis_profile: {
          provider: { id: "ghidra", version: "12.1.4" },
          parameters: {
            import_mode: "ephemeral-source-immutable",
            annotation_policy: "atomic-function-entry-metadata-v1",
            analyzer_preset: "ghidra-default",
          },
        },
        normalized_result: [
          {
            address: "0x401000",
            value: "fixture_main",
            procedure: {
              external: false,
              thunk: false,
              thunk_target: null,
            },
          },
        ],
      });

      const beforeOverview = harness.calls.length;
      const mcpOverview = sessionEvidence(
        session,
        (
          await mcp.callTool({
            name: "binary_overview",
            arguments: {},
          })
        ).structuredContent,
      );
      const directOverview = await new EnhancedTools(session).execute(
        "binary_overview",
        {},
      );
      if (!directOverview.ok) throw directOverview.error;
      expect(harness.calls.slice(beforeOverview)).toEqual([
        "read_binary_inventory_summary",
      ]);
      expect(mcpOverview.normalized_result).toEqual(directOverview.value);
      expect(mcpOverview).toMatchObject({
        provider: { id: "rea-workflow" },
        confidence: "derived",
        normalized_result: {
          document: "fixture",
          segment_count: 1,
          procedure_count: 1,
          string_count: 2,
          segments: [{ name: ".text", length: 256 }],
        },
      });

      const pseudocode = sessionEvidence(
        session,
        (
          await mcp.callTool({
            name: "procedure_pseudo_code",
            arguments: { procedure: "fixture_main" },
          })
        ).structuredContent,
      );
      expect(pseudocode).toMatchObject({
        operation: "procedure_pseudo_code",
        provider: { id: "ghidra", version: "12.1.4" },
        normalized_result: expect.stringContaining("return 42"),
        limitations: expect.arrayContaining([
          expect.stringContaining("not text-equivalent to Hopper"),
        ]),
      });

      const analyzed = sessionEvidence(
        session,
        (
          await mcp.callTool({
            name: "analyze_function",
            arguments: { procedure: "fixture_main", detail: "complete" },
          })
        ).structuredContent,
      );
      expect(analyzed).toMatchObject({
        operation: "analyze_function",
        provider: { id: "ghidra", version: "12.1.4" },
        normalized_result: {
          procedure: {
            address: "0x401000",
            name: "fixture_main",
            classification: {
              external: false,
              thunk: false,
              provenance: "ghidra-function-manager",
            },
          },
          pseudocode: "int fixture_main(void) { return 42; }",
          outgoing_references: [
            {
              kind: { available: true, provenance: "ghidra-reference-manager" },
            },
          ],
          limitations: expect.arrayContaining([
            expect.stringContaining("indirect flows without target addresses"),
            expect.stringContaining(
              "not original source or Hopper-equivalent text",
            ),
          ]),
        },
        limitations: expect.arrayContaining([
          expect.stringContaining("default auto-analysis complete"),
          expect.stringContaining(
            "original executable bytes are never written",
          ),
        ]),
      });
      const directAnalyzed = await new EnhancedTools(session).execute(
        "analyze_function",
        { procedure: "fixture_main" },
      );
      if (!directAnalyzed.ok) throw directAnalyzed.error;
      expect(analyzed.normalized_result).toEqual(directAnalyzed.value);
    } finally {
      await harness.close();
    }
  }, 30_000);
});
