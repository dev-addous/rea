import { open, writeFile, type FileHandle } from "node:fs/promises";
import { join } from "node:path";
import { expect, it, onTestFinished, vi } from "vitest";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { NativeMacOSProvider } from "./NativeMacOSProvider.js";
import { MachoCommandNamesLimitError } from "./MachoCommandNames.js";
import {
  NativeFixtureRunner,
  nativeMachoTargetForFile,
} from "../../tests/fixtures/nativeCommands.js";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";

const control = vi.hoisted(() => ({
  read: undefined as undefined | (() => Promise<never>),
}));
vi.mock("./MachoCommandNames.js", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("./MachoCommandNames.js")>();
  return {
    ...actual,
    readMachoCommandNames: (
      ...args: Parameters<typeof actual.readMachoCommandNames>
    ) =>
      control.read === undefined
        ? actual.readMachoCommandNames(...args)
        : control.read(),
  };
});

it("reports target mutation after a throwing binary reader and retains the producer failure", async () => {
  const root = await createTestTempDirectory("rea-macho-target-mutation-");
  const path = join(root, "fixture.macho");
  await writeFile(path, "selected source bytes");
  const client = new NativeMacOSProvider(
    {},
    new NativeFixtureRunner({
      lipo: `Non-fat file: ${path} is architecture: arm64\n`,
    }),
    "darwin",
  ).createClient(await nativeMachoTargetForFile(path));
  control.read = async () => {
    await writeFile(path, "changed source bytes!");
    throw new MachoCommandNamesLimitError(23, "records");
  };
  try {
    const result = await client.execute("inspect_macho", {});
    if (result.ok) throw new Error("Expected target mutation refusal");
    expect(result.error._tag).toBe("AnalysisArtifactChangedError");
    expect(projectAnalysisError(result.error)).toMatchObject({
      details: {
        diagnostics: {
          previous_error: {
            code: "resource_constraint",
            details: { operation: "inspect_macho" },
          },
        },
      },
    });
    expect(result.error.cleanupIncomplete).toBe(false);
  } finally {
    control.read = undefined;
    await client.close();
  }
});

it("retains cancellation and a throwing reader's failure through final verification", async () => {
  const root = await createTestTempDirectory("rea-macho-reader-cancel-");
  const path = join(root, "fixture.macho");
  await writeFile(path, "selected source bytes");
  const client = new NativeMacOSProvider(
    {},
    new NativeFixtureRunner({
      lipo: `Non-fat file: ${path} is architecture: arm64\n`,
    }),
    "darwin",
  ).createClient(await nativeMachoTargetForFile(path));
  const controller = new AbortController();
  const reason = new Error("cancel after reader failure");
  control.read = async () => {
    controller.abort(reason);
    throw new MachoCommandNamesLimitError(23, "records");
  };
  try {
    const result = await client.execute(
      "inspect_macho",
      {},
      { signal: controller.signal },
    );
    if (result.ok) throw new Error("Expected cancellation");
    expect(result.error._tag).toBe("AnalysisCancelledError");
    expect(projectAnalysisError(result.error)).toMatchObject({
      details: {
        diagnostics: { previous_error: { code: "resource_constraint" } },
      },
    });
    expect(result.error.cleanupIncomplete).toBe(false);
  } finally {
    control.read = undefined;
    await client.close();
  }
});

it("retains mutation and reader failure while descriptor cleanup is retried", async () => {
  const root = await createTestTempDirectory("rea-macho-reader-close-");
  const path = join(root, "fixture.macho");
  await writeFile(path, "selected source bytes");
  const target = await nativeMachoTargetForFile(path);
  const probe = await open(path, "r");
  const prototype = Object.getPrototypeOf(probe) as FileHandle;
  await probe.close();
  const client = new NativeMacOSProvider(
    {},
    new NativeFixtureRunner({
      lipo: `Non-fat file: ${path} is architecture: arm64\n`,
    }),
    "darwin",
  ).createClient(target);
  const state = { failing: true, attempts: 0 };
  const original = prototype.stat;
  const stat = vi
    .spyOn(prototype, "stat")
    .mockImplementationOnce(async function (
      this: FileHandle,
      ...args: Parameters<FileHandle["stat"]>
    ) {
      const close = this.close.bind(this);
      this.close = async () => {
        state.attempts += 1;
        if (state.failing)
          throw new Error("controlled Mach-O descriptor close failure");
        await close();
      };
      return Reflect.apply(original, this, args);
    });
  control.read = async () => {
    await writeFile(path, "changed source bytes!");
    throw new MachoCommandNamesLimitError(23, "records");
  };
  onTestFinished(async () => {
    control.read = undefined;
    stat.mockRestore();
    state.failing = false;
    await client.close();
  });
  const result = await client.execute("inspect_macho", {});
  if (result.ok) throw new Error("Expected cleanup failure");
  expect(result.error.cleanupIncomplete).toBe(true);
  expect(result.error.cleanupResources).toEqual([path]);
  expect(result.error.cleanupPrimary?._tag).toBe(
    "AnalysisArtifactChangedError",
  );
  expect(result.error.cleanupPrimary?.diagnostics).toMatchObject({
    previous_error: { code: "resource_constraint" },
  });
  expect(state.attempts).toBe(1);
  state.failing = false;
  expect((await client.close()).ok).toBe(true);
  expect(result.error.cleanupIncomplete).toBe(false);
  expect(state.attempts).toBe(2);
});

it("retains a returned command failure and captured output when close fails", async () => {
  const root = await createTestTempDirectory("rea-macho-command-close-");
  const path = join(root, "fixture.macho");
  await writeFile(path, "selected source bytes");
  const target = await nativeMachoTargetForFile(path);
  const probe = await open(path, "r");
  const prototype = Object.getPrototypeOf(probe) as FileHandle;
  await probe.close();
  const client = new NativeMacOSProvider(
    {},
    new NativeFixtureRunner({ lipo: "unrecognized producer output\n" }),
    "darwin",
  ).createClient(target);
  const state = { failing: true, attempts: 0 };
  const original = prototype.stat;
  const stat = vi
    .spyOn(prototype, "stat")
    .mockImplementationOnce(async function (
      this: FileHandle,
      ...args: Parameters<FileHandle["stat"]>
    ) {
      const close = this.close.bind(this);
      this.close = async () => {
        state.attempts += 1;
        if (state.failing)
          throw new Error("controlled Mach-O descriptor close failure");
        await close();
      };
      return Reflect.apply(original, this, args);
    });
  onTestFinished(async () => {
    stat.mockRestore();
    state.failing = false;
    await client.close();
  });
  const result = await client.execute("inspect_macho", {});
  if (result.ok) throw new Error("Expected cleanup failure");
  expect(result.error.cleanupIncomplete).toBe(true);
  expect(result.error.cleanupResources).toEqual([path]);
  expect(result.error.cleanupPrimary).toMatchObject({
    _tag: "AnalysisOutputError",
    capturedOutput: { stdout: "unrecognized producer output\n", exit_code: 0 },
  });
  expect(projectAnalysisError(result.error)).toMatchObject({
    details: { diagnostics: { previous_error: { code: "unreadable_output" } } },
  });
  expect(state.attempts).toBe(1);
  state.failing = false;
  expect((await client.close()).ok).toBe(true);
  expect(result.error.cleanupIncomplete).toBe(false);
  expect(state.attempts).toBe(2);
});

it("preserves a returned command failure and late cancellation through close retry", async () => {
  const root = await createTestTempDirectory("rea-macho-command-cancel-close-");
  const path = join(root, "fixture.macho");
  await writeFile(path, "selected source bytes");
  const target = await nativeMachoTargetForFile(path);
  const probe = await open(path, "r");
  const prototype = Object.getPrototypeOf(probe) as FileHandle;
  await probe.close();
  const client = new NativeMacOSProvider(
    {},
    new NativeFixtureRunner({ lipo: "unrecognized producer output\n" }),
    "darwin",
  ).createClient(target);
  const controller = new AbortController();
  const cancelReason = new Error("cancelled during descriptor close");
  const state = { failing: true };
  const original = prototype.stat;
  const stat = vi
    .spyOn(prototype, "stat")
    .mockImplementationOnce(async function (
      this: FileHandle,
      ...args: Parameters<FileHandle["stat"]>
    ) {
      const close = this.close.bind(this);
      this.close = async () => {
        if (state.failing) {
          controller.abort(cancelReason);
          throw new Error("controlled Mach-O descriptor close failure");
        }
        await close();
      };
      return Reflect.apply(original, this, args);
    });
  onTestFinished(async () => {
    stat.mockRestore();
    state.failing = false;
    await client.close();
  });
  const result = await client.execute(
    "inspect_macho",
    {},
    { signal: controller.signal },
  );
  if (result.ok) throw new Error("Expected cleanup failure");
  expect(result.error.cleanupIncomplete).toBe(true);
  expect(result.error.cleanupPrimary).toMatchObject({
    _tag: "AnalysisOutputError",
    capturedOutput: { stdout: "unrecognized producer output\n" },
  });
  expect(projectAnalysisError(result.error)).toMatchObject({
    details: {
      diagnostics: {
        previous_error: { code: "unreadable_output" },
        completion_cancellation: { code: "cancelled" },
      },
    },
  });
  state.failing = false;
  expect((await client.close()).ok).toBe(true);
  expect(result.error.cleanupIncomplete).toBe(false);
});
