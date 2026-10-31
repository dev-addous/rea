import { createHash } from "node:crypto";
import { constants, type Stats } from "node:fs";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { release } from "node:os";
import { isAbsolute, join } from "node:path";
import { z } from "zod";

import { safeParseJson } from "../domain/safeJson.js";

/** Bumped when the entry layout or the key material changes meaning. */
const CACHE_FORMAT = 1;
const HELPER_NAME = "reader";
const MANIFEST_NAME = "manifest.json";
const MAX_MANIFEST_BYTES = 4096;
// The compiled helper is about 240 KiB; refuse to hash anything far larger.
const MAX_HELPER_BYTES = 16 * 1024 * 1024;

const manifestSchema = z.strictObject({
  format: z.literal(CACHE_FORMAT),
  key: z.string().regex(/^[a-f0-9]{64}$/u),
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  size: z.int().positive(),
});

const sha256 = (value: string | Uint8Array): string =>
  createHash("sha256").update(value).digest("hex");

/** Per-user namespace REA owns for the compiled Darwin ownership helper. */
export const defaultDarwinHelperCacheDirectory = (home: string): string =>
  join(home, "Library/Caches/rea/process-helper");

/**
 * Only the default toolchain shares a helper: a caller-selected compiler or
 * module cache keeps every helper write inside the boundary the caller chose.
 */
export const darwinHelperCacheDirectory = (selection: {
  readonly home: string | undefined;
  readonly compilerSelected: boolean;
  readonly moduleCachePath: string | undefined;
}): string | undefined =>
  selection.compilerSelected ||
  (selection.moduleCachePath ?? "") !== "" ||
  selection.home === undefined ||
  !isAbsolute(selection.home)
    ? undefined
    : defaultDarwinHelperCacheDirectory(selection.home);

/** Only the current user may have written an entry REA will execute. */
const privatelyOwned = (stats: Stats, uid: number): boolean =>
  stats.uid === uid && (stats.mode & 0o022) === 0;

const isMissing = (cause: unknown): boolean =>
  cause instanceof Error && "code" in cause && cause.code === "ENOENT";

/** A linked or vanished entry file is invalid data, not an unusable cache. */
const openEntryFile = (path: string) =>
  open(path, constants.O_RDONLY | constants.O_NOFOLLOW).catch(() => undefined);

interface HelperBytes {
  readonly sha256: string;
  readonly size: number;
}

/** Hash the opened file itself so a replaced path cannot pass for it. */
const readPrivateExecutable = async (
  path: string,
  uid: number,
): Promise<HelperBytes | undefined> => {
  const handle = await openEntryFile(path);
  if (handle === undefined) return undefined;
  try {
    const stats = await handle.stat();
    if (
      !stats.isFile() ||
      !privatelyOwned(stats, uid) ||
      (stats.mode & 0o100) === 0 ||
      stats.size === 0 ||
      stats.size > MAX_HELPER_BYTES
    )
      return undefined;
    const bytes = await handle.readFile();
    if (bytes.byteLength !== stats.size) return undefined;
    return { sha256: sha256(bytes), size: bytes.byteLength };
  } finally {
    await handle.close();
  }
};

const readManifest = async (
  path: string,
  uid: number,
): Promise<z.output<typeof manifestSchema> | undefined> => {
  const handle = await openEntryFile(path);
  if (handle === undefined) return undefined;
  try {
    const stats = await handle.stat();
    if (
      !stats.isFile() ||
      !privatelyOwned(stats, uid) ||
      stats.size > MAX_MANIFEST_BYTES
    )
      return undefined;
    const decoded = safeParseJson(await handle.readFile("utf8"));
    if (!decoded.ok) return undefined;
    const parsed = manifestSchema.safeParse(decoded.value);
    return parsed.success ? parsed.data : undefined;
  } finally {
    await handle.close();
  }
};

/** Result of looking up the helper for this exact source and toolchain. */
export type DarwinHelperLookup =
  | { readonly kind: "hit"; readonly executable: string }
  | { readonly kind: "miss"; readonly key: string }
  | { readonly kind: "unavailable" };

/**
 * Content-addressed reuse of the compiled ownership helper across REA
 * processes. Every failure falls back to the per-process compile: the cache
 * never fails an ownership operation and never executes an entry that is not
 * a private, current-user, digest-verified copy for this key. Same-user
 * tampering is outside this boundary, as it is for the per-process helper.
 */
export const createDarwinHelperCache = (options: {
  readonly directory: string;
  readonly sources: readonly string[];
  /** Compiler selection and toolchain environment that shape the output. */
  readonly toolchain: Readonly<Record<string, string>>;
}) => {
  const uid = process.getuid?.();
  let key: Promise<string> | undefined;
  const cacheKey = (): Promise<string> =>
    (key ??= Promise.all(
      options.sources.map(async (source) => sha256(await readFile(source))),
    ).then((sources) =>
      sha256(
        JSON.stringify({
          format: CACHE_FORMAT,
          sources,
          toolchain: options.toolchain,
          architecture: process.arch,
          os_release: release(),
        }),
      ),
    ));

  /** The cache root exists, is a real directory, and only this user writes it. */
  const trustedRoot = async (owner: number): Promise<boolean> => {
    await mkdir(options.directory, { recursive: true, mode: 0o700 });
    const stats = await lstat(options.directory);
    return stats.isDirectory() && privatelyOwned(stats, owner);
  };

  const lookup = async (): Promise<DarwinHelperLookup> => {
    if (uid === undefined) return { kind: "unavailable" };
    try {
      if (!(await trustedRoot(uid))) return { kind: "unavailable" };
      const entryKey = await cacheKey();
      const entry = join(options.directory, entryKey);
      let entryStats: Stats;
      try {
        entryStats = await lstat(entry);
      } catch (cause: unknown) {
        if (isMissing(cause)) return { kind: "miss", key: entryKey };
        throw cause;
      }
      // Another user's or a linked entry is never executed or removed.
      if (!entryStats.isDirectory() || entryStats.uid !== uid)
        return { kind: "unavailable" };
      const executable = join(entry, HELPER_NAME);
      if (privatelyOwned(entryStats, uid)) {
        const manifest = await readManifest(join(entry, MANIFEST_NAME), uid);
        const helper =
          manifest?.key === entryKey
            ? await readPrivateExecutable(executable, uid)
            : undefined;
        if (
          helper !== undefined &&
          helper.sha256 === manifest?.sha256 &&
          helper.size === manifest.size
        )
          return { kind: "hit", executable };
      }
      // Malformed data in this user's entry is safely removable; the
      // compile that follows republishes a verified copy.
      await rm(entry, { recursive: true, force: true });
      return { kind: "miss", key: entryKey };
    } catch {
      return { kind: "unavailable" };
    }
  };

  /**
   * Atomically publish a verified copy and return the shared helper to run.
   * macOS assesses each new executable file on its first launch (about 0.3 s),
   * so running the shared copy pays that once for every later process.
   */
  const publish = async (
    entryKey: string,
    compiled: string,
  ): Promise<string | undefined> => {
    if (uid === undefined) return undefined;
    let staging: string | undefined;
    try {
      if (!(await trustedRoot(uid))) return undefined;
      staging = await mkdtemp(join(options.directory, ".publish-"));
      const copied = join(staging, HELPER_NAME);
      await copyFile(compiled, copied, constants.COPYFILE_EXCL);
      await chmod(copied, 0o700);
      const helper = await readPrivateExecutable(copied, uid);
      if (helper === undefined) return undefined;
      await writeFile(
        join(staging, MANIFEST_NAME),
        JSON.stringify({
          format: CACHE_FORMAT,
          key: entryKey,
          sha256: helper.sha256,
          size: helper.size,
        }),
        { mode: 0o600, flag: "wx" },
      );
      const entry = join(options.directory, entryKey);
      try {
        await rename(staging, entry);
        staging = undefined;
        return join(entry, HELPER_NAME);
      } catch {
        // A concurrent publisher won; run its entry only once it verifies.
        const winner = await lookup();
        return winner.kind === "hit" ? winner.executable : undefined;
      }
    } catch {
      // Publication is an optimization; the caller keeps its own helper.
      return undefined;
    } finally {
      if (staging !== undefined)
        await rm(staging, { recursive: true, force: true }).catch(
          () => undefined,
        );
    }
  };

  return { lookup, publish };
};

export type DarwinHelperCache = ReturnType<typeof createDarwinHelperCache>;
