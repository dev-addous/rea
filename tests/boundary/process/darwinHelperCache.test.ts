import {
  chmod,
  lstat,
  mkdir,
  readFile,
  readdir,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { expect, it, vi } from "vitest";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import {
  createDarwinHelperCache,
  darwinHelperCacheDirectory,
} from "../../../src/process/DarwinHelperCache.js";
import { createDarwinProcessRunTokenReader } from "../../../src/process/DarwinProcessRunTokenReader.js";
import { createSystemProcessOwnershipHost } from "../../../src/process/ProcessOwnershipObservation.js";

const posix = process.platform !== "win32";
const onDarwin = process.platform === "darwin";

const exists = (path: string): Promise<boolean> =>
  lstat(path).then(
    () => true,
    () => false,
  );

/** One cache over fixture sources, plus a compiled helper to publish. */
const fixtureCache = async (prefix: string) => {
  const directory = await createTestTempDirectory(prefix);
  const source = join(directory, "Reader.swift");
  await writeFile(source, "// helper source v1\n");
  const compiled = join(directory, "compiled-reader");
  await writeFile(compiled, "#!/bin/sh\necho compiled\n");
  await chmod(compiled, 0o755);
  const root = join(directory, "cache", "process-helper");
  const create = (toolchain: Record<string, string> = { compiler: "xcrun" }) =>
    createDarwinHelperCache({ directory: root, sources: [source], toolchain });
  return { directory, source, compiled, root, create };
};

const missKey = async (
  cache: ReturnType<typeof createDarwinHelperCache>,
): Promise<string> => {
  const lookup = await cache.lookup();
  if (lookup.kind !== "miss")
    throw new Error(`Expected a miss: ${lookup.kind}`);
  return lookup.key;
};

it.skipIf(!posix)(
  "publishes a private verified entry that a later process reuses",
  async () => {
    const fixture = await fixtureCache("rea-helper-cache-publish-");
    const first = fixture.create();
    const key = await missKey(first);
    const published = await first.publish(key, fixture.compiled);
    expect(published).toBe(join(fixture.root, key, "reader"));
    expect((await stat(fixture.root)).mode & 0o777).toBe(0o700);
    expect((await stat(join(fixture.root, key))).mode & 0o777).toBe(0o700);
    expect((await stat(published ?? "")).mode & 0o777).toBe(0o700);
    expect(
      (await stat(join(fixture.root, key, "manifest.json"))).mode & 0o777,
    ).toBe(0o600);
    expect(await readdir(fixture.root)).toEqual([key]);
    // A fresh cache object stands in for the next REA process.
    expect(await fixture.create().lookup()).toEqual({
      kind: "hit",
      executable: published,
    });
  },
);

it.skipIf(!posix)(
  "keys entries on helper source bytes and toolchain selection",
  async () => {
    const fixture = await fixtureCache("rea-helper-cache-key-");
    const key = await missKey(fixture.create());
    expect(await missKey(fixture.create({ compiler: "swiftc" }))).not.toBe(key);
    await writeFile(fixture.source, "// helper source v2\n");
    expect(await missKey(fixture.create())).not.toBe(key);
  },
);

it.skipIf(!posix)(
  "removes this user's corrupt, mislabelled, or loosened entries before republishing",
  async () => {
    const fixture = await fixtureCache("rea-helper-cache-invalid-");
    const corruptions: Record<string, (entry: string) => Promise<void>> = {
      "changed helper bytes": (entry) =>
        writeFile(join(entry, "reader"), "#!/bin/sh\necho replaced\n"),
      "manifest for another key": async (entry) => {
        const manifest = JSON.parse(
          await readFile(join(entry, "manifest.json"), "utf8"),
        ) as Record<string, unknown>;
        await writeFile(
          join(entry, "manifest.json"),
          JSON.stringify({ ...manifest, key: "0".repeat(64) }),
        );
      },
      "group-writable entry": (entry) => chmod(entry, 0o770),
      "group-writable helper": (entry) => chmod(join(entry, "reader"), 0o770),
      "malformed manifest": async (entry) => {
        await writeFile(join(entry, "manifest.json"), "{");
      },
      "linked helper": async (entry) => {
        const target = join(fixture.directory, "elsewhere");
        await writeFile(target, "#!/bin/sh\necho elsewhere\n");
        await chmod(target, 0o700);
        const { rm } = await import("node:fs/promises");
        await rm(join(entry, "reader"));
        await symlink(target, join(entry, "reader"));
      },
    };
    for (const [name, corrupt] of Object.entries(corruptions)) {
      const cache = fixture.create();
      const key = await missKey(cache);
      const published = await cache.publish(key, fixture.compiled);
      expect(published, name).toBeDefined();
      await corrupt(join(fixture.root, key));
      expect(await fixture.create().lookup(), name).toEqual({
        kind: "miss",
        key,
      });
      expect(await exists(join(fixture.root, key)), name).toBe(false);
    }
  },
);

it.skipIf(!posix)(
  "never executes or removes a linked entry or an untrusted cache root",
  async () => {
    const fixture = await fixtureCache("rea-helper-cache-untrusted-");
    const cache = fixture.create();
    const key = await missKey(cache);
    const valid = join(fixture.directory, "valid-entry");
    await mkdir(valid, { mode: 0o700 });
    await symlink(valid, join(fixture.root, key));
    expect(await fixture.create().lookup()).toEqual({ kind: "unavailable" });
    expect((await lstat(join(fixture.root, key))).isSymbolicLink()).toBe(true);

    const loose = await fixtureCache("rea-helper-cache-loose-root-");
    await mkdir(loose.root, { recursive: true });
    await chmod(loose.root, 0o777);
    const looseCache = loose.create();
    expect(await looseCache.lookup()).toEqual({ kind: "unavailable" });
    expect(await looseCache.publish("a".repeat(64), loose.compiled)).toBe(
      undefined,
    );
    expect(await readdir(loose.root)).toEqual([]);

    const blocked = await fixtureCache("rea-helper-cache-blocked-root-");
    await writeFile(join(blocked.directory, "cache"), "not a directory");
    expect(await blocked.create().lookup()).toEqual({ kind: "unavailable" });
  },
);

it.skipIf(!posix)(
  "keeps the first concurrent publication and leaves no staging directory",
  async () => {
    const fixture = await fixtureCache("rea-helper-cache-race-");
    const key = await missKey(fixture.create());
    const results = await Promise.all(
      Array.from({ length: 4 }, () =>
        fixture.create().publish(key, fixture.compiled),
      ),
    );
    expect(new Set(results)).toEqual(
      new Set([join(fixture.root, key, "reader")]),
    );
    expect(await readdir(fixture.root)).toEqual([key]);
  },
);

it.skipIf(!posix)(
  "returns no shared helper when the compiled output is unusable",
  async () => {
    const fixture = await fixtureCache("rea-helper-cache-unusable-");
    const key = await missKey(fixture.create());
    expect(
      await fixture.create().publish(key, join(fixture.directory, "absent")),
    ).toBeUndefined();
    const empty = join(fixture.directory, "empty");
    await writeFile(empty, "");
    expect(await fixture.create().publish(key, empty)).toBeUndefined();
    expect(await readdir(fixture.root)).toEqual([]);
  },
);

it("shares a helper only for the default toolchain and an absolute home", () => {
  const select = (
    overrides: Partial<Parameters<typeof darwinHelperCacheDirectory>[0]>,
  ) =>
    darwinHelperCacheDirectory({
      home: "/Users/analyst",
      compilerSelected: false,
      moduleCachePath: undefined,
      ...overrides,
    });
  expect(select({})).toBe("/Users/analyst/Library/Caches/rea/process-helper");
  // An empty module cache setting keeps the default, as documented.
  expect(select({ moduleCachePath: "" })).toBe(
    "/Users/analyst/Library/Caches/rea/process-helper",
  );
  expect(select({ moduleCachePath: "/boundary/modules" })).toBeUndefined();
  expect(select({ compilerSelected: true })).toBeUndefined();
  expect(select({ home: "relative/home" })).toBeUndefined();
  expect(select({ home: undefined })).toBeUndefined();
});

/** Fake xcrun whose helper answers token reads; counts compilations. */
const writeCountingCompiler = async (directory: string, blocking = false) => {
  const executable = join(directory, "fake-xcrun");
  const countPath = join(directory, "compile-count");
  const rootsPath = join(directory, "compile-roots");
  const helper = `#!/usr/bin/env node
const pids = process.argv.slice(2).filter((value) => value !== "--identities");
process.stdout.write(JSON.stringify({ results: pids.map((pid) => ({ pid: Number(pid), state: "readable", run_id: "fixture" })) }));
`;
  await writeFile(
    executable,
    `#!/usr/bin/env node
const fs = process.getBuiltinModule("node:fs");
const path = process.getBuiltinModule("node:path");
const output = process.argv[process.argv.indexOf("-o") + 1];
fs.appendFileSync(${JSON.stringify(countPath)}, "x");
fs.appendFileSync(${JSON.stringify(rootsPath)}, path.dirname(output) + "\\n");
if (${String(blocking)}) setInterval(() => {}, 1000);
else {
  fs.writeFileSync(output, ${JSON.stringify(helper)});
  fs.chmodSync(output, 0o755);
}
`,
  );
  await chmod(executable, 0o755);
  return {
    executable,
    compilations: async () =>
      (await readFile(countPath, "utf8").catch(() => "")).length,
    roots: async () =>
      (await readFile(rootsPath, "utf8").catch(() => ""))
        .split("\n")
        .filter((line) => line !== ""),
  };
};

const fixtureProcess = {
  pid: 123,
  parentPid: 1,
  processGroupId: 123,
  state: "S",
  command: "fixture",
};

it.skipIf(!posix)(
  "runs the shared helper in later readers without recompiling and keeps it after close",
  async () => {
    const directory = await createTestTempDirectory("rea-helper-cache-reader-");
    const helperCacheDirectory = join(directory, "process-helper");
    const compiler = await writeCountingCompiler(directory);
    const create = () =>
      createDarwinProcessRunTokenReader({
        compiler: { kind: "xcrun", executable: compiler.executable },
        helperCacheDirectory,
      });
    const first = create();
    let shared: string;
    try {
      shared = await first.prepare();
      expect(shared.startsWith(join(helperCacheDirectory, ""))).toBe(true);
      expect((await first.read([fixtureProcess])).get(123)).toEqual({
        state: "readable",
        runId: "fixture",
      });
    } finally {
      await first.close();
    }
    const [compileRoot] = await compiler.roots();
    expect(compileRoot).toBeDefined();
    expect(await exists(compileRoot ?? "")).toBe(false);
    expect(await exists(shared)).toBe(true);

    const second = create();
    try {
      expect(await second.prepare()).toBe(shared);
      expect((await second.read([fixtureProcess])).get(123)).toEqual({
        state: "readable",
        runId: "fixture",
      });
    } finally {
      await second.close();
    }
    expect(await compiler.compilations()).toBe(1);
    expect(await exists(shared)).toBe(true);
  },
);

it.skipIf(!posix)(
  "publishes nothing when helper compilation is cancelled",
  async () => {
    const directory = await createTestTempDirectory("rea-helper-cache-cancel-");
    const helperCacheDirectory = join(directory, "process-helper");
    const compiler = await writeCountingCompiler(directory, true);
    const reader = createDarwinProcessRunTokenReader({
      compiler: { kind: "xcrun", executable: compiler.executable },
      helperCacheDirectory,
    });
    const controller = new AbortController();
    try {
      const prepared = reader.prepare(controller.signal);
      const deadline = Date.now() + 10_000;
      while ((await compiler.compilations()) === 0 && Date.now() < deadline)
        await new Promise((resolve) => setTimeout(resolve, 10));
      controller.abort(new Error("caller cancelled"));
      await expect(prepared).rejects.toThrow("caller cancelled");
    } finally {
      await reader.close();
    }
    expect(await readdir(helperCacheDirectory)).toEqual([]);
    const [compileRoot] = await compiler.roots();
    expect(await exists(compileRoot ?? "")).toBe(false);
  },
);

it.skipIf(!onDarwin)(
  "reuses the real default-toolchain helper in a later host without compiling",
  async () => {
    const home = await createTestTempDirectory("rea-helper-cache-home-");
    const cacheRoot = join(home, "Library/Caches/rea/process-helper");
    const environment: NodeJS.ProcessEnv = { ...process.env, HOME: home };
    delete environment.REA_DARWIN_SWIFTC_PATH;
    delete environment.REA_DARWIN_MODULE_CACHE_PATH;
    const prepare = async (selected: NodeJS.ProcessEnv) => {
      const host = createSystemProcessOwnershipHost("darwin", selected);
      try {
        await host.prepare?.(AbortSignal.timeout(180_000));
        const current = (await host.listProcesses()).find(
          ({ pid }) => pid === process.pid,
        );
        if (current === undefined || host.processIdentities === undefined)
          throw new Error("Darwin host omitted the current process identity");
        expect(
          (await host.processIdentities([current])).get(process.pid),
        ).toMatchObject({ state: "readable" });
      } finally {
        await host.close?.();
      }
    };
    await prepare(environment);
    const [key, ...others] = await readdir(cacheRoot);
    expect(others).toEqual([]);
    const helper = join(cacheRoot, key ?? "", "reader");
    const published = await stat(helper);
    // A compile would need a per-run root under TMPDIR; deny it.
    const noTemporary = join(home, "no-temporary");
    await mkdir(noTemporary, { mode: 0o500 });
    vi.stubEnv("TMPDIR", noTemporary);
    try {
      await prepare(environment);
    } finally {
      vi.unstubAllEnvs();
    }
    expect((await stat(helper)).ino).toBe(published.ino);
    expect(await readdir(cacheRoot)).toEqual([key]);
    expect(await readdir(noTemporary)).toEqual([]);
  },
);
