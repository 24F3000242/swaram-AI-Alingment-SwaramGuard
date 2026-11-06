import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { ModePill } from "./ModePill";

describe("ModePill", () => {
  it("renders 'Blocked at gateway' ONLY when mode is explicitly 'enforced'", () => {
    const htmlEnforced = renderToStaticMarkup(<ModePill mode="enforced" decision="block" />);
    expect(htmlEnforced.toLowerCase()).toContain("blocked");
    expect(htmlEnforced).toContain("Blocked at gateway");
  });

  it("NEVER contains the word 'blocked' when mode is 'enforce' (policy configuration)", () => {
    // 'enforce' is a configuration setting, NOT confirmation that an action was executed/blocked
    const htmlEnforceConfig = renderToStaticMarkup(<ModePill mode="enforce" decision="block" />);
    expect(htmlEnforceConfig.toLowerCase()).not.toContain("blocked");
    expect(htmlEnforceConfig).toContain("Would deny (replay)");
  });

  it("NEVER contains the word 'blocked' in simulation mode, even when decision is block", () => {
    const htmlSimBlock = renderToStaticMarkup(<ModePill mode="simulation" decision="block" />);
    expect(htmlSimBlock.toLowerCase()).not.toContain("blocked");
    expect(htmlSimBlock).toContain("Would deny (replay)");

    const htmlSimWouldBlock = renderToStaticMarkup(<ModePill mode="simulation" decision="would_block" />);
    expect(htmlSimWouldBlock.toLowerCase()).not.toContain("blocked");
    expect(htmlSimWouldBlock).toContain("Would deny (replay)");
  });

  it("renders 'Would pause (replay)' when decision is pause in simulation mode without 'blocked'", () => {
    const htmlSimPause = renderToStaticMarkup(<ModePill mode="simulation" decision="pause" />);
    expect(htmlSimPause.toLowerCase()).not.toContain("blocked");
    expect(htmlSimPause).toContain("Would pause (replay)");
  });

  it("renders 'Alert only' when decision is alert or allow in simulation mode without 'blocked'", () => {
    const htmlSimAlert = renderToStaticMarkup(<ModePill mode="simulation" decision="alert" />);
    expect(htmlSimAlert.toLowerCase()).not.toContain("blocked");
    expect(htmlSimAlert).toContain("Alert only");
  });

  it("never calls a live containment without a denied action 'blocked'", () => {
    const html = renderToStaticMarkup(<ModePill mode="enforced" decision="pause" outcome="contained" />);
    expect(html).toContain("Paused live");
    expect(html.toLowerCase()).not.toContain("blocked");
  });
});
