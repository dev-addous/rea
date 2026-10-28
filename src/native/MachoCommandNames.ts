import {
  MachoLoadCommandCursor,
  readMachoLoadCommandTableHeader,
} from "../domain/apple/machoLoadCommands.js";
import { readMachoSegmentHeader } from "../domain/apple/machoSegmentHeader.js";
import { readMachoSectionHeader } from "../domain/apple/machoSectionHeader.js";
import { createHash } from "node:crypto";

const DYLIB_COMMANDS = new Set([
  0xc, 0xd, 0x18, 0x80000018, 0x1f, 0x8000001f, 0x20, 0x23, 0x80000023,
]);
const LC_STR_COMMANDS = new Set([
  ...DYLIB_COMMANDS,
  0x6,
  0x7,
  0x9,
  0x10,
  0xe,
  0xf,
  0x12,
  0x13,
  0x14,
  0x15,
  0x8000001c,
  0x27,
  0x39,
]);

// Fields with fixed uint32 layouts in mach-o/loader.h. Keep these names at
// the binary owner so a downstream projection need not reinterpret text.
const FIXED_WORD_FIELDS: ReadonlyMap<number, readonly string[]> = new Map([
  [0x2, ["symoff", "nsyms", "stroff", "strsize"]],
  [0x3, ["offset", "size"]],
  [
    0xb,
    [
      "ilocalsym",
      "nlocalsym",
      "iextdefsym",
      "nextdefsym",
      "iundefsym",
      "nundefsym",
      "tocoff",
      "ntoc",
      "modtaboff",
      "nmodtab",
      "extrefsymoff",
      "nextrefsyms",
      "indirectsymoff",
      "nindirectsyms",
      "extreloff",
      "nextrel",
      "locreloff",
      "nlocrel",
    ],
  ],
  [0x16, ["offset", "nhints"]],
  [0x17, ["cksum"]],
  [0x1d, ["dataoff", "datasize"]],
  [0x1e, ["dataoff", "datasize"]],
  [0x21, ["cryptoff", "cryptsize", "cryptid"]],
  [
    0x22,
    [
      "rebase_off",
      "rebase_size",
      "bind_off",
      "bind_size",
      "weak_bind_off",
      "weak_bind_size",
      "lazy_bind_off",
      "lazy_bind_size",
      "export_off",
      "export_size",
    ],
  ],
  [
    0x80000022,
    [
      "rebase_off",
      "rebase_size",
      "bind_off",
      "bind_size",
      "weak_bind_off",
      "weak_bind_size",
      "lazy_bind_off",
      "lazy_bind_size",
      "export_off",
      "export_size",
    ],
  ],
  [0x26, ["dataoff", "datasize"]],
  [0x29, ["dataoff", "datasize"]],
  [0x2b, ["dataoff", "datasize"]],
  [0x2c, ["cryptoff", "cryptsize", "cryptid", "pad"]],
  [0x2e, ["dataoff", "datasize"]],
  [0x80000033, ["dataoff", "datasize"]],
  [0x80000034, ["dataoff", "datasize"]],
  [0x36, ["dataoff", "datasize"]],
  [0x37, ["dataoff", "datasize"]],
  [0x38, ["dataoff", "datasize"]],
]);

/** Read exact ranges from an already admitted and identity-verified slice. */
export type MachoRangeReader = (
  offset: number,
  size: number,
) => Promise<Uint8Array>;

/** Producer-derived output capacity exceeded while retaining binary strings. */
export class MachoCommandNamesLimitError extends Error {
  constructor(
    readonly maximum: number,
    readonly unit: "bytes" | "records",
  ) {
    super(`Mach-O load-command ${unit} exceed the retained output budget`);
  }
}

export interface MachoCommandNames {
  readonly sliceSize: number;
  readonly header: {
    readonly wide: boolean;
    readonly littleEndian: boolean;
    readonly cpuType: number;
    readonly cpuSubtype: number;
    readonly fileType: number;
    readonly flags: number;
  };
  readonly commands: readonly {
    readonly index: number;
    readonly command: number;
    readonly offset: number;
    readonly size: number;
    /** Every byte after the command header belongs to a decoded field. */
    readonly fullyDecoded?: boolean;
    /** Whole-command digest when it fits the retained output allowance. */
    readonly rawSha256: string | null;
    readonly fixedFields?: Readonly<Record<string, number>>;
    readonly segmentName?: Uint8Array;
    readonly segment?: {
      readonly address: bigint;
      readonly memorySize: bigint;
      readonly fileOffset: bigint;
      readonly fileSize: bigint;
      readonly maxProtection: number;
      readonly protection: number;
      readonly flags: number;
    };
    readonly sections?: readonly {
      readonly name: Uint8Array;
      readonly segmentName: Uint8Array;
      readonly address: bigint;
      readonly size: bigint;
      readonly fileOffset: number;
      readonly alignmentExponent: number;
      readonly relocationOffset: number;
      readonly relocationCount: number;
      readonly reserved1: number;
      readonly reserved2: number;
      readonly reserved3?: number;
      readonly flags: number;
    }[];
    readonly commandString?: Uint8Array;
    readonly commandStringOffset?: number;
    readonly dylib?: {
      readonly nameOffset: number;
      readonly currentVersion: number;
      readonly compatibilityVersion: number;
      readonly encoding:
        | { readonly kind: "timestamp"; readonly timestamp: number }
        | { readonly kind: "use"; readonly flags: number };
    };
    readonly legacyBuild?: {
      readonly version: number;
      readonly sdk: number;
    };
    readonly linkerOptions?: readonly Uint8Array[];
    readonly note?: {
      readonly owner: Uint8Array;
      readonly offset: bigint;
      readonly size: bigint;
    };
    readonly fileset?: {
      readonly address: bigint;
      readonly fileOffset: bigint;
      readonly entryId: Uint8Array;
      readonly reserved: number;
    };
    readonly prebound?: {
      readonly moduleCount: number;
      readonly linkedModulesOffset: number;
      readonly linkedModules: Uint8Array;
    };
    readonly fvmlib?: {
      readonly minorVersion: number;
      readonly headerAddress: number;
    };
    readonly fvmfile?: { readonly headerAddress: number };
    readonly uuid?: Uint8Array;
    readonly entrypoint?: {
      readonly offset: bigint;
      readonly stackSize: bigint;
    };
    readonly build?: {
      readonly platform: number;
      readonly minimumOs: number;
      readonly sdk: number;
      readonly tools: readonly {
        readonly tool: number;
        readonly version: number;
      }[];
    };
  }[];
}

/**
 * Walk only fixed records and declared strings from a selected thin image.
 * The caller owns identity, cancellation, closing, and the per-string byte cap.
 */
export const readMachoCommandNames = async (
  read: MachoRangeReader,
  imageSize: number,
  maximumStringBytes: number,
  maximumRecords: number,
): Promise<MachoCommandNames> => {
  if (
    !Number.isSafeInteger(maximumStringBytes) ||
    maximumStringBytes < 0 ||
    !Number.isSafeInteger(maximumRecords) ||
    maximumRecords < 0
  )
    throw new TypeError("Mach-O read limits must be nonnegative safe integers");
  const exact = async (offset: number, size: number): Promise<Uint8Array> => {
    if (
      !Number.isSafeInteger(offset) ||
      !Number.isSafeInteger(size) ||
      offset < 0 ||
      size < 0 ||
      offset > imageSize - size
    )
      throw new TypeError("Mach-O range exceeds selected slice");
    const value = await read(offset, size);
    if (value.byteLength !== size)
      throw new TypeError("Mach-O range is truncated");
    return value;
  };
  const header = await exact(0, Math.min(32, imageSize));
  const parsed = readMachoLoadCommandTableHeader(header, imageSize);
  if (!parsed.ok) throw new TypeError(parsed.error);
  if (parsed.value === null)
    throw new TypeError("Selected slice is not Mach-O");
  const table = parsed.value;
  const cursor = new MachoLoadCommandCursor(table);
  if (table.commandCount > maximumRecords)
    throw new MachoCommandNamesLimitError(maximumRecords, "records");
  let records = table.commandCount;
  let retainedStringBytes = 0;
  const retain = (bytes: Uint8Array): Uint8Array => {
    if (bytes.byteLength > maximumStringBytes - retainedStringBytes)
      throw new MachoCommandNamesLimitError(maximumStringBytes, "bytes");
    retainedStringBytes += bytes.byteLength;
    return bytes;
  };
  const commands: MachoCommandNames["commands"][number][] = [];
  while (cursor.nextOffset !== null) {
    const row = cursor.read(
      await exact(table.headerSize + cursor.nextOffset, 8),
    );
    if (!row.ok) throw new TypeError(row.error);
    const frame = row.value;
    const at = table.headerSize + frame.offset;
    const fixedNames = FIXED_WORD_FIELDS.get(frame.command);
    let fixedFields: Record<string, number> | undefined;
    if (fixedNames !== undefined) {
      const byteLength = fixedNames.length * 4;
      if (frame.size < 8 + byteLength)
        throw new TypeError("Mach-O fixed command fields are truncated");
      const bytes = await exact(at + 8, byteLength);
      const view = new DataView(
        bytes.buffer,
        bytes.byteOffset,
        bytes.byteLength,
      );
      fixedFields = Object.fromEntries(
        fixedNames.map((name, index) => [
          name,
          view.getUint32(index * 4, table.littleEndian),
        ]),
      );
    }
    const segmentWide =
      frame.command === 0x19 ? true : frame.command === 1 ? false : null;
    let segmentName: Uint8Array | undefined;
    let segmentFacts: MachoCommandNames["commands"][number]["segment"];
    let sections:
      | NonNullable<MachoCommandNames["commands"][number]["sections"]>[number][]
      | undefined;
    if (segmentWide !== null) {
      const segmentHeaderSize = segmentWide ? 72 : 56;
      if (frame.size < segmentHeaderSize)
        throw new TypeError("Mach-O segment is truncated");
      const segmentBytes = await exact(at, segmentHeaderSize);
      const segment = readMachoSegmentHeader(
        segmentBytes,
        segmentWide,
        table.littleEndian,
      );
      if (!segment.ok) throw new TypeError(segment.error.message);
      const width = segmentWide ? 80 : 68;
      if (
        segment.value.sectionCount >
        Math.floor((frame.size - segmentHeaderSize) / width)
      )
        throw new TypeError("Mach-O section table is truncated");
      if (segment.value.sectionCount > maximumRecords - records)
        throw new MachoCommandNamesLimitError(maximumRecords, "records");
      records += segment.value.sectionCount;
      segmentName = retain(segment.value.nameBytes);
      const segmentView = new DataView(
        segmentBytes.buffer,
        segmentBytes.byteOffset,
        segmentBytes.byteLength,
      );
      segmentFacts = {
        address: segment.value.address,
        memorySize: segment.value.memorySize,
        fileOffset: segment.value.fileOffset,
        fileSize: segment.value.fileSize,
        maxProtection: segment.value.maxProtection,
        protection: segment.value.protection,
        flags: segmentView.getUint32(segmentWide ? 68 : 52, table.littleEndian),
      };
      sections = [];
      for (let i = 0; i < segment.value.sectionCount; i++) {
        const sectionBytes = await exact(
          at + segmentHeaderSize + i * width,
          width,
        );
        const section = readMachoSectionHeader(
          sectionBytes,
          segmentWide,
          table.littleEndian,
        );
        if (!section.ok) throw new TypeError(section.error.message);
        const sectionView = new DataView(
          sectionBytes.buffer,
          sectionBytes.byteOffset,
          sectionBytes.byteLength,
        );
        sections.push({
          name: retain(section.value.nameBytes),
          segmentName: retain(section.value.segmentNameBytes),
          address: section.value.address,
          size: section.value.size,
          fileOffset: section.value.offset,
          alignmentExponent: sectionView.getUint32(
            segmentWide ? 52 : 44,
            table.littleEndian,
          ),
          relocationOffset: sectionView.getUint32(
            segmentWide ? 56 : 48,
            table.littleEndian,
          ),
          relocationCount: sectionView.getUint32(
            segmentWide ? 60 : 52,
            table.littleEndian,
          ),
          reserved1: sectionView.getUint32(
            segmentWide ? 68 : 60,
            table.littleEndian,
          ),
          reserved2: sectionView.getUint32(
            segmentWide ? 72 : 64,
            table.littleEndian,
          ),
          ...(segmentWide
            ? { reserved3: sectionView.getUint32(76, table.littleEndian) }
            : {}),
          flags: section.value.flags,
        });
      }
    }
    // Dylib and rpath commands own an lc_str at offset 8. Retain bytes up to
    // the first NUL without allocating the command's full declared extent.
    let commandString: Uint8Array | undefined;
    let commandStringOffset: number | undefined;
    let dylib: MachoCommandNames["commands"][number]["dylib"];
    if (LC_STR_COMMANDS.has(frame.command)) {
      if (frame.size < 12)
        throw new TypeError("Mach-O command string offset is truncated");
      const data = await exact(at + 8, 4);
      const offset = new DataView(
        data.buffer,
        data.byteOffset,
        data.byteLength,
      ).getUint32(0, table.littleEndian);
      const minimum = DYLIB_COMMANDS.has(frame.command)
        ? 24
        : frame.command === 0x6 ||
            frame.command === 0x7 ||
            frame.command === 0x10
          ? 20
          : frame.command === 0x9
            ? 16
            : 12;
      if (offset < minimum || offset >= frame.size)
        throw new TypeError("Mach-O command string offset is invalid");
      const limit = Math.min(frame.size - offset, maximumStringBytes + 1);
      const bytes = await exact(at + offset, limit);
      const end = bytes.indexOf(0);
      if (end < 0) {
        if (limit < frame.size - offset)
          throw new MachoCommandNamesLimitError(maximumStringBytes, "bytes");
        throw new TypeError("Mach-O command string is unterminated");
      }
      commandString = retain(bytes.slice(0, end));
      commandStringOffset = offset;
      if (DYLIB_COMMANDS.has(frame.command)) {
        const fixed = await exact(at + 12, 12);
        const view = new DataView(
          fixed.buffer,
          fixed.byteOffset,
          fixed.byteLength,
        );
        const marker = view.getUint32(0, table.littleEndian);
        const useEncoding =
          (frame.command === 0xc || frame.command === 0x80000018) &&
          offset === 28 &&
          marker === 0x1a741800;
        if (useEncoding && frame.size < 28)
          throw new TypeError("Mach-O dylib use command is truncated");
        const flags = useEncoding ? await exact(at + 24, 4) : undefined;
        dylib = {
          nameOffset: offset,
          currentVersion: view.getUint32(4, table.littleEndian),
          compatibilityVersion: view.getUint32(8, table.littleEndian),
          encoding:
            flags === undefined
              ? { kind: "timestamp", timestamp: marker }
              : {
                  kind: "use",
                  flags: new DataView(
                    flags.buffer,
                    flags.byteOffset,
                    flags.byteLength,
                  ).getUint32(0, table.littleEndian),
                },
        };
      }
    }
    let prebound: MachoCommandNames["commands"][number]["prebound"];
    if (frame.command === 0x10) {
      if (frame.size < 20)
        throw new TypeError("Mach-O prebound dylib command is truncated");
      const data = await exact(at + 12, 8);
      const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
      const moduleCount = view.getUint32(0, table.littleEndian);
      const linkedModulesOffset = view.getUint32(4, table.littleEndian);
      const length = Math.ceil(moduleCount / 8);
      if (linkedModulesOffset < 20 || linkedModulesOffset > frame.size - length)
        throw new TypeError(
          "Mach-O prebound module bitmap exceeds its command",
        );
      if (length > maximumStringBytes - retainedStringBytes)
        throw new MachoCommandNamesLimitError(maximumStringBytes, "bytes");
      prebound = {
        moduleCount,
        linkedModulesOffset,
        linkedModules: retain(await exact(at + linkedModulesOffset, length)),
      };
    }
    let fvmlib: MachoCommandNames["commands"][number]["fvmlib"];
    if (frame.command === 0x6 || frame.command === 0x7) {
      if (frame.size < 20)
        throw new TypeError("Mach-O fvmlib command is truncated");
      const data = await exact(at + 12, 8);
      const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
      fvmlib = {
        minorVersion: view.getUint32(0, table.littleEndian),
        headerAddress: view.getUint32(4, table.littleEndian),
      };
    }
    let fvmfile: MachoCommandNames["commands"][number]["fvmfile"];
    if (frame.command === 0x9) {
      if (frame.size < 16)
        throw new TypeError("Mach-O fvmfile command is truncated");
      const data = await exact(at + 12, 4);
      fvmfile = {
        headerAddress: new DataView(
          data.buffer,
          data.byteOffset,
          data.byteLength,
        ).getUint32(0, table.littleEndian),
      };
    }
    let linkerOptions: Uint8Array[] | undefined;
    if (frame.command === 0x2d) {
      if (frame.size < 12)
        throw new TypeError("Mach-O linker option count is truncated");
      const countBytes = await exact(at + 8, 4);
      const count = new DataView(
        countBytes.buffer,
        countBytes.byteOffset,
        countBytes.byteLength,
      ).getUint32(0, table.littleEndian);
      if (count > maximumRecords - records)
        throw new MachoCommandNamesLimitError(maximumRecords, "records");
      if (count > frame.size - 12)
        throw new TypeError("Mach-O linker option table is truncated");
      records += count;
      linkerOptions = [];
      let offset = 12;
      let current: number[] = [];
      while (linkerOptions.length < count && offset < frame.size) {
        const length = Math.min(frame.size - offset, 4096);
        const bytes = await exact(at + offset, length);
        offset += length;
        for (const byte of bytes) {
          if (byte === 0) {
            linkerOptions.push(retain(Uint8Array.from(current)));
            current = [];
            if (linkerOptions.length === count) break;
          } else {
            if (current.length >= maximumStringBytes)
              throw new MachoCommandNamesLimitError(
                maximumStringBytes,
                "bytes",
              );
            current.push(byte);
          }
        }
      }
      if (linkerOptions.length !== count)
        throw new TypeError("Mach-O linker option is unterminated");
    }
    let legacyBuild: MachoCommandNames["commands"][number]["legacyBuild"];
    if ([0x24, 0x25, 0x2f, 0x30].includes(frame.command)) {
      if (frame.size < 16)
        throw new TypeError("Mach-O minimum version command is truncated");
      const bytes = await exact(at + 8, 8);
      const view = new DataView(
        bytes.buffer,
        bytes.byteOffset,
        bytes.byteLength,
      );
      legacyBuild = {
        version: view.getUint32(0, table.littleEndian),
        sdk: view.getUint32(4, table.littleEndian),
      };
    }
    let note: MachoCommandNames["commands"][number]["note"];
    if (frame.command === 0x31) {
      if (frame.size < 40)
        throw new TypeError("Mach-O note command is truncated");
      const data = await exact(at + 8, 32);
      const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
      note = {
        owner: retain(data.slice(0, 16)),
        offset: view.getBigUint64(16, table.littleEndian),
        size: view.getBigUint64(24, table.littleEndian),
      };
    }
    let fileset: MachoCommandNames["commands"][number]["fileset"];
    if (frame.command === 0x80000035) {
      if (frame.size < 32)
        throw new TypeError("Mach-O fileset command is truncated");
      const data = await exact(at + 8, 24);
      const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
      const offset = view.getUint32(16, table.littleEndian);
      if (offset < 32 || offset >= frame.size)
        throw new TypeError("Mach-O fileset entry string offset is invalid");
      const length = Math.min(frame.size - offset, maximumStringBytes + 1);
      const value = await exact(at + offset, length);
      const end = value.indexOf(0);
      if (end < 0) {
        if (length < frame.size - offset)
          throw new MachoCommandNamesLimitError(maximumStringBytes, "bytes");
        throw new TypeError("Mach-O fileset entry string is unterminated");
      }
      fileset = {
        address: view.getBigUint64(0, table.littleEndian),
        fileOffset: view.getBigUint64(8, table.littleEndian),
        entryId: retain(value.slice(0, end)),
        reserved: view.getUint32(20, table.littleEndian),
      };
    }
    let uuid: Uint8Array | undefined;
    if (frame.command === 0x1b) {
      if (frame.size < 24)
        throw new TypeError("Mach-O UUID command is truncated");
      uuid = (await exact(at + 8, 16)).slice();
    }
    let entrypoint: MachoCommandNames["commands"][number]["entrypoint"];
    if (frame.command === 0x80000028) {
      if (frame.size < 24)
        throw new TypeError("Mach-O entrypoint command is truncated");
      const bytes = await exact(at + 8, 16);
      const view = new DataView(
        bytes.buffer,
        bytes.byteOffset,
        bytes.byteLength,
      );
      entrypoint = {
        offset: view.getBigUint64(0, table.littleEndian),
        stackSize: view.getBigUint64(8, table.littleEndian),
      };
    }
    let build: MachoCommandNames["commands"][number]["build"];
    if (frame.command === 0x32) {
      if (frame.size < 24)
        throw new TypeError("Mach-O build version command is truncated");
      const header = await exact(at + 8, 16);
      const view = new DataView(
        header.buffer,
        header.byteOffset,
        header.byteLength,
      );
      const toolCount = view.getUint32(12, table.littleEndian);
      if (toolCount > Math.floor((frame.size - 24) / 8))
        throw new TypeError("Mach-O build tool table is truncated");
      if (toolCount > maximumRecords - records)
        throw new MachoCommandNamesLimitError(maximumRecords, "records");
      records += toolCount;
      const tools: { tool: number; version: number }[] = [];
      for (let i = 0; i < toolCount; i++) {
        const tool = await exact(at + 24 + i * 8, 8);
        const toolView = new DataView(
          tool.buffer,
          tool.byteOffset,
          tool.byteLength,
        );
        tools.push({
          tool: toolView.getUint32(0, table.littleEndian),
          version: toolView.getUint32(4, table.littleEndian),
        });
      }
      build = {
        platform: view.getUint32(0, table.littleEndian),
        minimumOs: view.getUint32(4, table.littleEndian),
        sdk: view.getUint32(8, table.littleEndian),
        tools,
      };
    }
    const fullyDecoded =
      (fixedNames !== undefined && frame.size === 8 + fixedNames.length * 4) ||
      (uuid !== undefined && frame.size === 24) ||
      (entrypoint !== undefined && frame.size === 24) ||
      (legacyBuild !== undefined && frame.size === 16) ||
      (segmentWide !== null &&
        sections !== undefined &&
        frame.size ===
          (segmentWide ? 72 : 56) +
            sections.length * (segmentWide ? 80 : 68)) ||
      (build !== undefined && frame.size === 24 + build.tools.length * 8);
    let rawSha256: string | null = null;
    if (!fullyDecoded && frame.size <= maximumStringBytes) {
      const digest = createHash("sha256");
      for (let position = 0; position < frame.size;) {
        const length = Math.min(64 * 1024, frame.size - position);
        digest.update(await exact(at + position, length));
        position += length;
      }
      rawSha256 = digest.digest("hex");
    }
    commands.push({
      index: frame.index,
      command: frame.command,
      offset: frame.offset,
      size: frame.size,
      fullyDecoded,
      rawSha256,
      ...(fixedFields === undefined ? {} : { fixedFields }),
      ...(segmentName === undefined ||
      sections === undefined ||
      segmentFacts === undefined
        ? {}
        : { segmentName, segment: segmentFacts, sections }),
      ...(commandString === undefined ? {} : { commandString }),
      ...(commandStringOffset === undefined ? {} : { commandStringOffset }),
      ...(dylib === undefined ? {} : { dylib }),
      ...(legacyBuild === undefined ? {} : { legacyBuild }),
      ...(linkerOptions === undefined ? {} : { linkerOptions }),
      ...(note === undefined ? {} : { note }),
      ...(fileset === undefined ? {} : { fileset }),
      ...(prebound === undefined ? {} : { prebound }),
      ...(fvmlib === undefined ? {} : { fvmlib }),
      ...(fvmfile === undefined ? {} : { fvmfile }),
      ...(uuid === undefined ? {} : { uuid }),
      ...(entrypoint === undefined ? {} : { entrypoint }),
      ...(build === undefined ? {} : { build }),
    });
  }
  const end = cursor.finish();
  if (!end.ok) throw new TypeError(end.error);
  return {
    sliceSize: imageSize,
    header: {
      wide: table.wide,
      littleEndian: table.littleEndian,
      cpuType: table.identity.cpuType,
      cpuSubtype: table.identity.cpuSubtype,
      fileType: table.fileType,
      flags: new DataView(
        header.buffer,
        header.byteOffset,
        header.byteLength,
      ).getUint32(24, table.littleEndian),
    },
    commands,
  };
};
