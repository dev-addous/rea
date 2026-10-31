#!/usr/bin/env node
// Write source-owned x86-64 ELF executables whose header entry Ghidra's ELF
// loader names `entry`. The bytes are never executed.
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export const ELF_ROLE_ENTRY = 0x400080n;
const BASE = 0x400000n;
const CODE = Buffer.from("b82a000000c3", "hex"); // mov eax, 42; ret
const CODE_OFFSET = Number(ELF_ROLE_ENTRY - BASE);

const sectionHeader = (fields) => {
  const header = Buffer.alloc(64);
  header.writeUInt32LE(fields.name, 0);
  header.writeUInt32LE(fields.type, 4);
  header.writeBigUInt64LE(fields.flags ?? 0n, 8);
  header.writeBigUInt64LE(fields.address ?? 0n, 16);
  header.writeBigUInt64LE(BigInt(fields.offset), 24);
  header.writeBigUInt64LE(BigInt(fields.size), 32);
  header.writeUInt32LE(fields.link ?? 0, 40);
  header.writeUInt32LE(fields.info ?? 0, 44);
  header.writeBigUInt64LE(fields.align ?? 1n, 48);
  header.writeBigUInt64LE(fields.entrySize ?? 0n, 56);
  return header;
};

/** One PT_LOAD image; `sections` optionally adds headers and their contents. */
const executable = (sections) => {
  const image = Buffer.alloc(CODE_OFFSET + CODE.length);
  image.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  image.writeUInt16LE(2, 16); // ET_EXEC
  image.writeUInt16LE(62, 18); // EM_X86_64
  image.writeUInt32LE(1, 20);
  image.writeBigUInt64LE(ELF_ROLE_ENTRY, 24);
  image.writeBigUInt64LE(64n, 32);
  image.writeUInt16LE(64, 52);
  image.writeUInt16LE(56, 54);
  image.writeUInt16LE(1, 56);
  image.writeUInt16LE(64, 58);
  image.writeUInt32LE(1, 64); // PT_LOAD
  image.writeUInt32LE(5, 68); // R|X
  image.writeBigUInt64LE(BASE, 80);
  image.writeBigUInt64LE(BASE, 88);
  image.writeBigUInt64LE(BigInt(image.length), 96);
  image.writeBigUInt64LE(BigInt(image.length), 104);
  image.writeBigUInt64LE(0x1000n, 112);
  image.set(CODE, CODE_OFFSET);
  if (sections.length === 0) return image;

  const all = [
    ...sections,
    { name: ".shstrtab", type: 3, data: Buffer.alloc(0) },
  ];
  const names = [0];
  let shstrtab = Buffer.from([0]);
  for (const section of all) {
    names.push(shstrtab.length);
    shstrtab = Buffer.concat([shstrtab, Buffer.from(`${section.name}\0`)]);
  }
  all.at(-1).data = shstrtab;
  const parts = [image];
  let offset = image.length;
  const headers = [sectionHeader({ name: 0, type: 0, offset: 0, size: 0 })];
  const align = () => {
    const padding = (8 - (offset % 8)) % 8;
    parts.push(Buffer.alloc(padding));
    offset += padding;
  };
  all.forEach((section, index) => {
    // Sections without an offset append their contents after the image.
    if (section.offset === undefined) align();
    headers.push(
      sectionHeader({
        ...section,
        name: names[index + 1],
        offset: section.offset ?? offset,
        size: section.data.length,
      }),
    );
    if (section.offset === undefined) {
      parts.push(section.data);
      offset += section.data.length;
    }
  });
  align();
  const bytes = Buffer.concat([...parts, ...headers]);
  bytes.writeBigUInt64LE(BigInt(offset), 40);
  bytes.writeUInt16LE(headers.length, 60);
  bytes.writeUInt16LE(headers.length - 1, 62);
  return bytes;
};

const text = {
  name: ".text",
  type: 1, // SHT_PROGBITS
  flags: 6n, // SHF_ALLOC|SHF_EXECINSTR
  address: ELF_ROLE_ENTRY,
  offset: CODE_OFFSET,
  data: CODE,
  align: 16n,
};
const symbol = Buffer.alloc(48);
symbol.writeUInt32LE(1, 24); // "entry" in .strtab
symbol.writeUInt8(0x12, 28); // STB_GLOBAL, STT_FUNC
symbol.writeUInt16LE(1, 30); // .text
symbol.writeBigUInt64LE(ELF_ROLE_ENTRY, 32);
symbol.writeBigUInt64LE(BigInt(CODE.length), 40);

/** Expected bridge `loader_role_label` for the function at the ELF header entry. */
export const ELF_ROLE_LABEL_FIXTURES = {
  // No symbol table: the loader creates and names the entry function.
  stripped: { label: "synthesized", bytes: executable([]) },
  // A genuine global FUNC symbol `entry` defines the header entry function.
  symbolized: {
    label: "artifact-symbol",
    bytes: executable([
      text,
      {
        name: ".symtab",
        type: 2, // SHT_SYMTAB
        data: symbol,
        link: 3,
        info: 1,
        align: 8n,
        entrySize: 24n,
      },
      { name: ".strtab", type: 3, data: Buffer.from("\0entry\0") },
    ]),
  },
  // MiniDebugInfo can supply stripped symbols that the bridge does not decode.
  minidebug: {
    label: "unexamined",
    bytes: executable([
      text,
      { name: ".gnu_debugdata", type: 1, data: Buffer.from("not-xz") },
    ]),
  },
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [directory] = process.argv.slice(2);
  if (directory === undefined)
    throw new Error("Usage: elf-role-label-fixture.mjs OUTPUT_DIRECTORY");
  for (const [name, fixture] of Object.entries(ELF_ROLE_LABEL_FIXTURES))
    await writeFile(join(directory, `${name}.elf`), fixture.bytes);
}
