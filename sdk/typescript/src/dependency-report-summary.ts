import {
  counts,
  verdictOrder,
  type Finding,
  type Report,
  type Section,
} from "./dependency-report-model.js";
import { escapeHtml as esc, prose } from "./dependency-report-audit.js";
import { dependencyVerdictLabels } from "./dependency-verdict-labels.js";
import { formatSecurityPolicyText } from "./security-policy.js";

function scope(finding: Finding): string {
  if (finding.kind === "stack") {
    const s = finding.assessment.scope;
    return [
      s.environment,
      s.cluster,
      s.service,
      s.container === s.service ? undefined : s.container,
      s.image_digest ?? s.image_tag,
      s.window.start + " to " + s.window.end,
    ]
      .filter(Boolean)
      .join(" · ");
  }
  const place = finding.item.place;
  return [
    place?.environment,
    place?.workload,
    place?.variant,
    place?.platform,
    place?.artifact,
  ]
    .filter(Boolean)
    .join(" · ");
}

type StackFinding = Extract<Finding, { kind: "stack" }>;

function samplingScope(finding: StackFinding) {
  const s = finding.assessment.scope;
  return [s.environment, s.cluster, s.service, s.container, s.image_tag]
    .filter((value, index, fields) => value && fields.indexOf(value) === index)
    .join(" · ");
}

function samplingWindow(finding: StackFinding) {
  const { start, end } = finding.assessment.scope.window;
  return start + " to " + end;
}

function samplingRows(findings: StackFinding[]) {
  const groups = Map.groupBy(findings, (f) => {
    const a = f.assessment;
    return JSON.stringify([
      a.queryId,
      a.groupId,
      samplingScope(f),
      a.scope.window,
    ]);
  });
  return [...groups.values()]
    .map((findings) => {
      const f = findings[0]!;
      const { assessment: a } = f;
      const observed = findings.filter((f) => f.assessment.observation).length;
      const status = [
        observed
          ? "Samples observed"
          : a.status === "no_match"
            ? "No matching sample"
            : "No sampling coverage",
        a.truncated === true ? "Incomplete capture" : undefined,
        a.truncated === null ? "Completeness unknown" : undefined,
        a.scopeConflicts.length ? "Scope conflict" : undefined,
      ].filter(Boolean);
      return `<tr><th scope="row">${esc(samplingScope(f) || "Scope unavailable")}</th><td>${esc(samplingWindow(f))}</td><td>${esc(status.join(" · "))}</td><td>${observed}</td><td><a href="#${f.id}">${esc(a.queryId)}</a></td></tr>`;
    })
    .join("");
}

export function stackOverview(section: Section): string {
  const { stack, prepared } = section;
  if (!stack || !prepared) return "";
  const findings = prepared.findings.filter((f) => f.kind === "stack");
  const sampled = findings.filter((f) => f.assessment.observation);
  const windows = new Set(findings.map(samplingWindow));
  const verdicts = verdictOrder
    .map((verdict) => {
      const matching = sampled.filter((f) => f.item.verdict === verdict);
      return matching.length
        ? `<li><a href="#${matching[0]!.id}" data-verdict="${verdict}">${esc(dependencyVerdictLabels[verdict])} · ${matching.length}</a></li>`
        : "";
    })
    .join("");
  const selected = sampled[0];
  const verdict = selected?.item.verdict;
  const condition = selected?.proof?.conditions.find(
    (condition) =>
      condition.status ===
      (verdict === "ruled_out"
        ? "ruled_out"
        : verdict === "exploitable"
          ? "met"
          : "unknown"),
  );
  const deciding = selected?.assessment.questionChecks?.[0]?.missingEvidence;
  const evidence =
    condition?.label ?? selected?.assessment.remainingQuestions[0];
  const coverage = stack.coverage;
  const limits = [
    ...new Set([...coverage.truncated, ...coverage.truncationUnknown]),
  ].length;
  const gaps = findings.length - sampled.length;
  return `<section class="stack-overview" aria-label="Investigation summary">
    <h2>Sampled path verdicts</h2>
    ${verdicts ? `<ul class="stack-verdicts">${verdicts}</ul>` : "<p>No sampled stacks were assessed.</p>"}
    ${stack.callerScope ? `<details class="stack-caller" open><summary>Caller scope</summary><p>${prose(stack.callerScope)}</p></details>` : ""}
    ${selected && evidence ? `<p><strong>${condition?.status === "ruled_out" ? "Ruled-out condition" : condition?.status === "met" ? "Supported condition" : "Open condition"} for <a href="#${selected.id}">this assessment</a></strong> · ${prose(evidence)}${condition ? " · " + prose(condition.explanation) : ""}</p>` : ""}
    ${deciding && deciding !== evidence ? `<p><strong>Missing evidence</strong> · ${prose(deciding)}</p>` : ""}
    <p><strong>Aggregate verdict</strong> · ${esc(dependencyVerdictLabels[stack.verdict])}</p>
    ${windows.size === 1 ? `<p><strong>Sampling window</strong> · ${esc([...windows][0]!)}</p>` : ""}
    <details class="stack-coverage">
      <summary>Sampling coverage · ${sampled.length} sampled · ${gaps} without a sample${limits ? ` · ${limits} incomplete or unverified work items` : ""}</summary>
      ${findings.length ? `<div class="stack-coverage-scroll" role="region" aria-label="Sampling coverage table" tabindex="0"><table><thead><tr><th scope="col">Scope</th><th scope="col">Window</th><th scope="col">Result</th><th scope="col">Samples</th><th scope="col">Query</th></tr></thead><tbody>${samplingRows(findings)}</tbody></table></div>` : ""}
    </details>
  </section>`;
}

/** Keep stdout scannable at the terminal. The Markdown and JSON retain the full evidence. */
export function summarizeDependencyReport(report: Report): string {
  const lines = [
    report.sections.length
      ? report.title
      : report.title + ": no published advisories found.",
  ];
  if (report.target)
    lines.push(
      "Repository " +
        report.target.repository +
        " · Analyzed commit " +
        report.target.sha,
    );
  for (const section of report.sections) {
    if (section.title !== report.title) lines.push("", section.title);
    if (section.pending) {
      lines.push(
        "Not investigated · Package investigation stopped before this advisory.",
      );
      continue;
    }
    if (section.blocked) {
      lines.push("Investigation blocked · " + section.blocked.reason);
      if (section.blocked.unblockCondition)
        lines.push("  Next: " + section.blocked.unblockCondition);
      continue;
    }
    const findings = section.prepared!.findings;
    const { reviewed, unresolved, breakdown } = counts(findings);
    const totals = section.stack
      ? [
          dependencyVerdictLabels[section.stack.verdict],
          `${section.stack.coverage.assessed}/${section.stack.coverage.total} stack items assessed`,
        ]
      : [reviewed + " reviewed " + (reviewed === 1 ? "use" : "uses")];
    for (const verdict of verdictOrder)
      if (
        breakdown[verdict] &&
        (!section.stack ||
          breakdown[verdict] !== findings.length ||
          section.stack.verdict !== verdict)
      )
        totals.push(
          `${dependencyVerdictLabels[verdict]}: ${breakdown[verdict]}`,
        );
    if (unresolved)
      totals.push(
        unresolved +
          " unresolved coverage " +
          (unresolved === 1 ? "item" : "items"),
      );
    lines.push(totals.join(" · "));
    if (section.stack) {
      const c = section.stack.coverage;
      const assessments = section.stack.assessments;
      const cutGroups = new Set(
        assessments
          .filter((a) => a.truncated)
          .map((a) => JSON.stringify([a.queryId, a.groupId])),
      ).size;
      const cutStacks = assessments.filter(
        (a) => a.observation?.framesTruncated,
      ).length;
      const limits = [
        cutGroups &&
          `${cutGroups} truncated capture ${cutGroups === 1 ? "group" : "groups"}`,
        cutStacks &&
          `${cutStacks} ${cutStacks === 1 ? "stack" : "stacks"} with truncated frames`,
        c.truncationUnknown.length &&
          c.truncationUnknown.length + " truncation unknown",
        c.noMatch.length && c.noMatch.length + " without a match",
        c.noCoverage.length && c.noCoverage.length + " without coverage",
        c.scopeConflicts.length && c.scopeConflicts.length + " scope conflicts",
      ].filter(Boolean);
      if (limits.length) lines.push("Capture limits: " + limits.join(" · "));
    }
    const scopes = findings.map(scope);
    const commonScope = new Set(scopes).size === 1 ? scopes[0] : undefined;
    if (commonScope) lines.push("Scope: " + commonScope);
    for (const [index, f] of findings.entries()) {
      const outcome =
        f.kind === "coverage"
          ? "Unresolved coverage"
          : dependencyVerdictLabels[f.item.verdict];
      const component =
        f.kind !== "coverage" && f.item.component
          ? f.item.component + "@" + (f.item.version ?? "unknown")
          : undefined;
      const site = f.anchor && f.anchor.path + ":" + f.anchor.line;
      const stack = f.kind === "stack" ? f.assessment : undefined;
      const label = stack?.use?.location ?? f.label;
      const sample = stack
        ? (stack.observation?.stackHash.slice(0, 12) ??
          stack.status.replaceAll("_", " "))
        : undefined;
      lines.push(
        "",
        `${index + 1}. ${[outcome, label, component, sample].filter(Boolean).join(" · ")}`,
      );
      if (site && site !== label)
        lines.push(
          "   " + (f.anchor?.kind === "call" ? "Call: " : "Reference: ") + site,
        );
      if (!commonScope && scopes[index])
        lines.push("   Scope: " + scopes[index]);
      const condition = f.item.openConditions?.[0];
      const question =
        stack?.remainingQuestions[0] ??
        condition?.decidingCheck ??
        condition?.question ??
        (f.kind === "coverage" ? f.item.handoff?.missing : undefined) ??
        f.item.place?.unresolvedQuestions[0];
      const unresolved =
        f.kind === "coverage" ||
        f.item.verdict === "unknown" ||
        f.item.verdict === "potentially_exploitable";
      if (unresolved && question && question !== f.item.reason)
        lines.push("   Next: " + question);
      else lines.push("   " + f.item.reason);
    }
    for (const note of section.check?.limitations ?? [])
      lines.push("  Gap: " + note);
  }
  if (report.contextHint) lines.push("", report.contextHint);
  return lines.map((line) => formatSecurityPolicyText(line)).join("\n");
}
