import { expect, test } from "bun:test";
import { affectedByFrozenVersion } from "../src/dependency-advisory-version";

test("a frozen PyPI version list only excludes releases it can compare", () => {
  const pkg = { ecosystem: "PyPI", name: "example" };
  function affected(version: string, versions: string[]) {
    return affectedByFrozenVersion(pkg, version, [
      {
        id: "test-advisory",
        url: "https://example.invalid/advisory",
        sha256: "a".repeat(64),
        affected: [{ package: pkg, versions }],
      },
    ]);
  }
  expect(affected("1.0.0", ["1.0"])).toBe(true);
  expect(affected("1.0.1", ["1.0"])).toBe(false);
  expect(affected("1.0a1", ["1.0a1"])).toBe(true);
  expect(affected("1.0a1", ["1.0-alpha1"])).toBe(true);
  expect(affected("2.1.0+cu121", ["2.1.0"])).toBe(true);
  expect(affected("2.1.0+cpu", ["2.1.0"])).toBe(true);
  expect(affected("2.1.0+cpu", ["2.1.0+cu121"])).toBe(false);
  expect(affected("2.1.0+CUDA_012", ["2.1.0+cuda.12"])).toBe(true);
  expect(affected("2.5.0rc1", ["2.5.0"])).toBe(false);
  expect(affected("2.5.0rc1", ["2.5.0-rc.1"])).toBe(true);
  expect(affected("1.0.post1", ["1.0-1"])).toBe(true);
  expect(affected("1.0.dev1", ["1.0"])).toBe(false);
  expect(affected("1.0+", ["1.0"])).toBeUndefined();
});
