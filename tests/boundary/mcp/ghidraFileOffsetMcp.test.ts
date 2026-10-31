import { access } from "node:fs/promises";

import { expect, it, vi } from "vitest";
import { z } from "zod";

import { AnalysisProviderRegistry } from "../../../src/application/binary/AnalysisProviderRegistry.js";
import { composeBinarySession } from "../../../src/application/binary/BinarySessionComposition.js";
import { runDirectAnalysis } from "../../../src/application/DirectAnalysis.js";
import type { DirectAnalysisDependencies } from "../../../src/application/DirectAnalysisDependencies.js";
import { projectCliAnalysisResult } from "../../../src/cli/projectCliAnalysisResult.js";
import { parseConfig } from "../../../src/config/parseConfig.js";
import { analysisCliErrorEnvelopeSchema } from "../../../src/contracts/errorSchemas.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { GhidraClient } from "../../../src/ghidra/GhidraClient.js";
import { ghidraProfileInstallationHost } from "../../../src/ghidra/GhidraInstallation.fixture.js";
import { GhidraProvider } from "../../../src/ghidra/GhidraProvider.js";
import { silentLogger } from "../../../src/logger.js";
import { createApplicationMcpHarness } from "../../fixtures/applicationMcpHarness.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";
import { GhidraFixtureLauncher } from "../providers/ghidra/ghidraClient.fixture.js";

// Only installation discovery and the Java bridge are simulated. The bridge
// fixture answers with the production address_to_file_offset codes; requests
// cross the real client socket, provider projection and public adapters.
const ghidraSession = (launcher: GhidraFixtureLauncher) => {
  const config = parseConfig({ GHIDRA_INSTALL_DIR: "/fixture/ghidra" });
  if (!config.ok) throw config.error;
  return composeBinarySession(
    new AnalysisProviderRegistry([
      new GhidraProvider(
        config.value,
        silentLogger,
        {},
        ghidraProfileInstallationHost,
        (options) =>
          new GhidraClient({
            ...options,
            platform: process.platform,
            launcher,
          }),
      ),
    ]),
  );
};

const expectReleased = async (launcher: GhidraFixtureLauncher) => {
  for (const root of launcher.runtimeRoots)
    await expect(access(root)).rejects.toMatchObject({ code: "ENOENT" });
  for (const child of launcher.processes)
    expect(child.exitCode !== null || child.signalCode !== null).toBe(true);
};

const BSS_MESSAGE =
  "Address 0x2004 is in uninitialized Ghidra memory block .bss";

it("reports file-backed, uninitialized and unmapped addresses through MCP without schema repair", async () => {
  const launcher = new GhidraFixtureLauncher();
  const harness = await createApplicationMcpHarness({
    session: ghidraSession(launcher),
    serverOptions: { logger: silentLogger },
    clientIdentity: { name: "ghidra-file-offset", version: "1" },
  });
  const call = (address: string) =>
    harness.client.callTool({
      name: "address_to_file_offset",
      arguments: { address },
    });
  // A per-address outcome must not mark the operation unavailable.
  const runId = async () => {
    const reply = await harness.client.callTool({
      name: "binary_session",
      arguments: {},
    });
    const status = z
      .object({
        result: z.object({
          analysis_run: z.object({ run_id: z.string() }),
          capabilities: z.array(
            z.object({
              groups: z.array(
                z.object({
                  operations: z.array(z.string()),
                  available: z.boolean(),
                }),
              ),
            }),
          ),
        }),
      })
      .parse(reply.structuredContent).result;
    expect(
      status.capabilities
        .flatMap(({ groups }) => groups)
        .filter(({ operations }) =>
          operations.includes("address_to_file_offset"),
        ),
    ).toEqual([expect.objectContaining({ available: true })]);
    return status.analysis_run.run_id;
  };
  try {
    const opened = await harness.client.callTool({
      name: "open_binary",
      arguments: { path: process.execPath, provider_id: "ghidra" },
    });
    expect(opened.isError).not.toBe(true);
    const mapped = await call("0x1005");
    expect(mapped.isError, JSON.stringify(mapped)).not.toBe(true);
    expect(parseEvidence(mapped.structuredContent).normalized_result).toEqual({
      address: "0x1005",
      file_offset: 5,
    });
    const run = await runId();

    // The caller's non-canonical spelling survives beside the canonical reason.
    const bss = parseMcpToolError(await call("0X2004")).error;
    expect(bss).toMatchObject({
      code: "invalid_request",
      category: "invalid_input",
      retryable: false,
      details: {
        operation: "address_to_file_offset",
        issues: [
          {
            path: ["address"],
            reason: "invalid_value",
            message: BSS_MESSAGE,
            observed: { address: "0X2004", file_mapping: "uninitialized" },
          },
        ],
        diagnostics: {
          diagnostic_scope: "request",
          remote_code: "address_uninitialized",
        },
      },
    });
    expect(bss.message.startsWith(`${BSS_MESSAGE}. `)).toBe(true);
    expect(bss).not.toHaveProperty("recovery");
    expect(bss.remediation.action).toContain("inspect_native_load_image");
    expect(bss.remediation.action).not.toContain("tools/list");
    expect(bss.details?.diagnostics).not.toHaveProperty("stdout");

    const unmapped = parseMcpToolError(await call("0x3000")).error;
    expect(unmapped).toMatchObject({
      code: "invalid_request",
      details: {
        issues: [
          {
            message: "Address 0x3000 is outside every Ghidra memory block",
            observed: { address: "0x3000", file_mapping: "unmapped" },
          },
        ],
        diagnostics: { remote_code: "address_unmapped" },
      },
    });
    expect(unmapped).not.toHaveProperty("recovery");

    // Malformed syntax is still an input-contract violation.
    const malformed = parseMcpToolError(await call("not-an-address")).error;
    expect(malformed).toMatchObject({
      code: "invalid_request",
      message: "Analysis input is invalid. Check the arguments and try again.",
      recovery: {
        kind: "inspect_input_contract",
        operation: "address_to_file_offset",
      },
      details: {
        issues: [{ path: ["address"], reason: "invalid_format" }],
      },
    });

    // Refusals keep the same provider session and operation availability.
    expect(await runId()).toBe(run);
    const remapped = await call("0x1000");
    expect(parseEvidence(remapped.structuredContent).normalized_result).toEqual(
      { address: "0x1000", file_offset: 0 },
    );
    expect(launcher.processes).toHaveLength(1);
    // The malformed spelling never reached the bridge.
    await vi.waitFor(() =>
      expect(
        launcher.requests.filter(
          (method) => method === "address_to_file_offset",
        ),
      ).toHaveLength(4),
    );
  } finally {
    await harness.close();
    await expectReleased(launcher);
  }
}, 30_000);

it("gives the CLI analysis path the same unbacked-address outcome as MCP", async () => {
  const launcher = new GhidraFixtureLauncher();
  const create = () => ghidraSession(launcher);
  const dependencies: DirectAnalysisDependencies = {
    readConfiguration: () =>
      parseConfig({ GHIDRA_INSTALL_DIR: "/fixture/ghidra" }),
    createBinarySession: create,
    createNativeDispatchBinarySession: create,
    createArtifactBinarySession: create,
    createNativeBinarySession: create,
    createManagedBinarySession: create,
  };
  try {
    const projected = analysisCliErrorEnvelopeSchema.parse(
      projectCliAnalysisResult(
        await runDirectAnalysis(
          dependencies,
          process.execPath,
          "address_to_file_offset",
          { address: "0X2004" },
          { providerId: "ghidra" },
        ),
      ),
    );
    expect(projected).toMatchObject({
      error: "Analysis failed",
      code: "invalid_request",
      category: "invalid_input",
      message: expect.stringMatching(/^Address 0x2004 is in uninitialized/u),
      remediation: {
        action: expect.stringContaining("inspect_native_load_image"),
      },
      details: {
        issues: [
          {
            path: ["address"],
            message: BSS_MESSAGE,
            observed: { address: "0X2004", file_mapping: "uninitialized" },
          },
        ],
        diagnostics: { remote_code: "address_uninitialized" },
      },
    });
    expect(projected).not.toHaveProperty("recovery");
  } finally {
    await expectReleased(launcher);
  }
}, 30_000);
