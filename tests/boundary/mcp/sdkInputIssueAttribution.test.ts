import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { expect, it } from "vitest";
import { z } from "zod";
import { createServer } from "../../../src/server/createServer.js";
import { EvidenceMcpServer } from "../../../src/server/EvidenceMcpServer.js";
import { createToolResultDelivery } from "../../../src/server/toolResult.js";
import { observed } from "../../fixtures/analysisExecution.js";
import { connectLocalToolsMcp } from "../../fixtures/localToolsMcp.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";

it("keeps concurrent SDK validation issues attached to their own tool call", async () => {
  let calls = 0;
  const server = createServer({
    kind: "fixed",
    analysis: {
      execute: () => {
        calls += 1;
        return Promise.resolve(observed(null));
      },
    },
  });
  const client = new Client({ name: "input-issue-attribution", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const [read, search, missing] = await Promise.all([
      client.callTool({
        name: "read_bytes",
        arguments: { address: 123, length: 0, document: false },
      }),
      client.callTool({
        name: "search_bytes",
        arguments: { pattern: 123, limit: 0, cursor: 23 },
      }),
      client.callTool({ name: "read_bytes", arguments: {} }),
    ]);
    expect(parseMcpToolError(read)).toMatchObject({
      error: {
        code: "invalid_request",
        details: {
          issues: expect.arrayContaining([
            { path: ["address"], reason: "invalid_type", expected: "string" },
            { path: ["length"], reason: "out_of_range", minimum: 1 },
            { path: ["document"], reason: "invalid_type", expected: "string" },
          ]),
        },
      },
    });
    expect(parseMcpToolError(search)).toMatchObject({
      error: {
        code: "invalid_request",
        details: {
          issues: expect.arrayContaining([
            { path: ["pattern"], reason: "invalid_type", expected: "string" },
            { path: ["limit"], reason: "out_of_range", minimum: 1 },
            { path: ["cursor"], reason: "invalid_type", expected: "string" },
          ]),
        },
      },
    });
    expect(parseMcpToolError(missing)).toMatchObject({
      error: {
        code: "invalid_request",
        details: {
          issues: expect.arrayContaining([
            {
              path: ["address"],
              reason: "missing_argument",
              expected: "string",
            },
          ]),
        },
      },
    });
    expect(calls).toBe(0);
    await expect(client.ping()).resolves.toBeDefined();
  } finally {
    await client.close();
    await server.close();
  }
});

it("preserves field diagnostics over production stdio and keeps serving", async () => {
  const { call, client } = await connectLocalToolsMcp();
  const result = await call("read_bytes", {
    address: 123,
    length: 0,
    document: false,
  });
  expect(parseMcpToolError(result)).toMatchObject({
    error: {
      code: "invalid_request",
      recovery: { kind: "inspect_input_contract", operation: "read_bytes" },
      details: {
        issues: expect.arrayContaining([
          { path: ["address"], reason: "invalid_type", expected: "string" },
          { path: ["length"], reason: "out_of_range", minimum: 1 },
          { path: ["document"], reason: "invalid_type", expected: "string" },
        ]),
      },
    },
  });
  await expect(client.ping()).resolves.toBeDefined();
});

it("discloses when bounded projection cannot retain union branch details", async () => {
  const info = { name: "bounded-issues", version: "1" };
  const server = new EvidenceMcpServer(
    info,
    { capabilities: {} },
    undefined,
    createToolResultDelivery(4096),
  );
  const branches = Array.from({ length: 256 }, (_, index) =>
    z.object({ [`field_${String(index)}`]: z.string() }),
  );
  const first = branches[0];
  const second = branches[1];
  if (first === undefined || second === undefined)
    throw new Error("missing branches");
  server.registerTool(
    "bounded_issues",
    {
      inputSchema: z.object({
        value: z.union([first, second, ...branches.slice(2)]),
      }),
    },
    async () => ({ content: [{ type: "text", text: "unexpected dispatch" }] }),
  );
  const client = new Client(info);
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const result = await client.callTool({
      name: "bounded_issues",
      arguments: { value: {} },
    });
    expect(parseMcpToolError(result)).toMatchObject({
      error: {
        code: "invalid_request",
        message: expect.stringContaining(
          "Field-level issue projection exceeded its response-derived allowance",
        ),
        details: { issues: [{ path: [], reason: "invalid_value" }] },
      },
    });
    await expect(client.ping()).resolves.toBeDefined();
  } finally {
    await client.close();
    await server.close();
  }
});
