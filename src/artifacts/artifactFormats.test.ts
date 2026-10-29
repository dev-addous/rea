import { describe, expect, it } from "vitest";

import { ARTIFACT_FORMAT_IDS } from "../domain/artifactGraph.js";
import {
  ZIP_PACKAGE_FORMATS,
  type ZipPackageFormat,
} from "../domain/zipPackageFormat.js";
import {
  ARTIFACT_FORMATS,
  ZIP_FAMILY_CAPABILITIES,
} from "./artifactFormats.js";
import { createArtifactReader } from "./createArtifactReader.js";

describe("artifact format descriptors", () => {
  it("covers every domain format id and no other id", () => {
    expect(Object.keys(ARTIFACT_FORMATS).sort()).toEqual(
      [...ARTIFACT_FORMAT_IDS].sort(),
    );
  });

  it("leaves unknown without a reader", () => {
    expect(ARTIFACT_FORMATS.unknown.createReader).toBeUndefined();
    expect(
      createArtifactReader("/unused", "unknown", {
        environment: {},
        unreadableDirectories: "omit",
      }),
    ).toBeUndefined();
  });

  it("shares one capability row across zip package families", () => {
    for (const id of ZIP_PACKAGE_FORMATS)
      expect(ARTIFACT_FORMATS[id]).toMatchObject(ZIP_FAMILY_CAPABILITIES);
    const zipIds = new Set<ZipPackageFormat>(ZIP_PACKAGE_FORMATS);
    for (const id of ARTIFACT_FORMAT_IDS)
      if (!zipIds.has(id as ZipPackageFormat))
        expect(ARTIFACT_FORMATS[id].zipFamily).toBe(false);
  });
});
