import { expect, test } from "bun:test";
import { renderDependencyReport } from "../src/dependency-report-renderer.js";
import { stackReport } from "./support/dependency-stack-report-fixture.js";

function count(html: string, selector: string) {
  let matches = 0;
  new HTMLRewriter()
    .on(selector, { element: () => void matches++ })
    .transform(html);
  return matches;
}

test("uses the query-selected sink for the title, path, and jump destination", () => {
  const report = stackReport();
  const [assessment] = report.assessments;
  const observation = {
    ...assessment.observation,
    sinkIndex: 2,
    sinkMatches: [
      { sinkId: "codec", rawIndex: 7 },
      { sinkId: "codec", rawIndex: 2 },
      { sinkId: "codec", rawIndex: 1 },
    ],
    frames: [
      { rawIndex: 1, frame: { name: "innerDecode", type: "native" } },
      { rawIndex: 2, frame: { name: "decode", type: "native" } },
      assessment.observation.frames[1]!,
      { rawIndex: 7, frame: { name: "outerDecode", type: "native" } },
    ],
    capturedFrameCount: 11,
  };
  const html = renderDependencyReport({
    ...report,
    assessments: [{ ...assessment, observation }],
  });
  expect(html).toContain("<h2>upload → decode</h2>");
  expect(count(html, "[data-assessed-sink]")).toBe(1);
  expect(
    count(
      html,
      '[data-assessed-sink][data-query-sink][data-frame-anchor="stack-1-1-raw-frame-2"]',
    ),
  ).toBe(1);
  expect(count(html, '[data-role="sink"][data-in-range="false"]')).toBe(2);
  expect(count(html, "[data-jump]")).toBe(1);
  expect(count(html, "#stack-1-1-frame-2 #stack-1-1-raw-frame-2")).toBe(1);
  expect(count(html, '[data-boundary-gap="before"]')).toBe(1);
  expect(count(html, '[data-boundary-gap="after"]')).toBe(1);
  expect(html).toContain("3 captured frames omitted before the saved frames");
  expect(html).toContain("1 captured frame omitted after the saved frames");
});

test("retains the repository citation without choosing between repeated sampled activations", () => {
  const report = stackReport();
  const [assessment] = report.assessments;
  const caller = {
    name: "caller",
    location: "src/codec.ts:3",
    type: "function",
  };
  const observation = {
    ...assessment.observation,
    frames: [
      ...assessment.observation.frames,
      { rawIndex: 2, frame: caller },
      { rawIndex: 6, frame: caller },
    ],
    bindings: [
      ...assessment.observation.bindings,
      {
        package: report.target.repository,
        sourceSha: report.target.sha,
        version: report.target.sha,
        provenance: "sample",
      },
    ],
  };
  const html = renderDependencyReport({
    ...report,
    assessments: [{ ...assessment, observation }],
  });
  expect(count(html, 'details[data-role="call_site"]')).toBe(0);
  expect(html).toContain("Multiple saved frames match the cited call site.");
  expect(html).toContain("<h3>Cited call site</h3>");
  expect(count(html, '[data-follow][aria-label="Next shown frame"]')).toBe(2);
});

test("retains empty sampled-stack notes and describes an inferred creator link", () => {
  const report = stackReport();
  const [assessment] = report.assessments;
  const html = renderDependencyReport({
    ...report,
    assessments: [
      {
        ...assessment,
        queryProvenance: { source: "inferred_creator_code" },
        observation: {
          ...assessment.observation,
          sourceIndex: null,
          sinkIndex: null,
          sinkMatches: [],
          bindings: [],
          frames: [],
          framesTruncated: null,
        },
      },
    ],
  });
  expect(html).toContain('aria-label="Inferred asynchronous link"');
  expect(html).toContain("Frame truncation unknown.");
  expect(html).toContain("No saved frames.");
  expect(count(html, "details[data-frame]")).toBe(0);
});

test("uses the unique catalog sink when the query selects a wrapper", () => {
  const report = stackReport();
  const [assessment] = report.assessments;
  const observation = {
    ...assessment.observation,
    sinkIndex: 2,
    frames: [
      ...assessment.observation.frames,
      { rawIndex: 2, frame: { name: "wrapper", type: "function" } },
    ],
  };
  const html = renderDependencyReport({
    ...report,
    assessments: [{ ...assessment, observation }],
  });
  expect(
    count(html, '[data-assessed-sink][data-frame-anchor$="raw-frame-0"]'),
  ).toBe(1);
  expect(count(html, '[data-query-sink][data-role="query_sink"]')).toBe(1);
});
