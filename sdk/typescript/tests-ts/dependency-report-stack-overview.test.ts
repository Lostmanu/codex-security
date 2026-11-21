import { expect, test } from "bun:test";
import { renderDependencyReport } from "../src/dependency-report-renderer.js";
import { stackReport } from "./support/dependency-stack-report-fixture.js";

test("puts the scoped verdict and capture limits before stack details", () => {
  const fixture = stackReport();
  const [sampled, gap] = fixture.assessments;
  const html = renderDependencyReport({
    ...fixture,
    callerScope: "Signed-in uploads",
    assessments: [
      gap,
      {
        ...sampled,
        verdict: "ruled_out",
        use: {
          ...sampled.use,
          verdict: "ruled_out",
          proof: {
            ...sampled.use.proof,
            conditions: [
              {
                label: "Decoder mode can reach the affected branch",
                status: "ruled_out",
                explanation: "The upload guard rejects that mode.",
                citations: [{ path: "src/codec.ts", line: 3 }],
              },
            ],
          },
        },
      },
    ],
  });
  const overview = html.slice(
    html.indexOf('<section class="stack-overview"'),
    html.indexOf('<article class="finding"'),
  );
  expect(overview).toContain('data-verdict="ruled_out">Ruled out · 1');
  expect(overview).not.toContain('data-verdict="unknown"');
  expect(overview).toContain("Signed-in uploads");
  expect(overview).toContain("The upload guard rejects that mode.");
  expect(overview).toContain("Aggregate verdict");
  expect(overview).toContain("1 sampled · 1 without a sample");
  expect(overview).toContain("No matching sample");
  expect(overview).toContain("Incomplete capture");
  expect(overview).toContain('href="#stack-1-2"');
});
