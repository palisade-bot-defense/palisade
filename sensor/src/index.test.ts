// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { PalisadeSensor } from "./index";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("PalisadeSensor", () => {
  it("sends only bucketed metadata", async () => {
    const request = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 204 }));
    const sensor = new PalisadeSensor({ endpoint: "/events", sessionId: "session-12345678", fetchImpl: request });
    sensor.start();
    window.dispatchEvent(new Event("scroll"));
    await sensor.flush();
    sensor.stop();

    expect(request).toHaveBeenCalledOnce();
    const init = request.mock.calls[0]?.[1];
    const payload = JSON.parse(String(init?.body)) as Record<string, unknown>;
    expect(payload).toHaveProperty("sessionId", "session-12345678");
    expect(JSON.stringify(payload)).not.toMatch(/innerHTML|key|text|target/i);
  });

  it("does not use headerless beacon when production proof is configured", async () => {
    const request = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 204 }));
    const sendBeacon = vi.fn().mockReturnValue(true);
    vi.stubGlobal("navigator", { ...navigator, sendBeacon });
    const sensor = new PalisadeSensor({
      endpoint: "/events",
      sessionId: "session-12345678",
      fetchImpl: request,
      proofProvider: async () => "synthetic-proof",
    });
    sensor.start();
    await sensor.flush(true);
    sensor.stop();

    expect(sendBeacon).not.toHaveBeenCalled();
    expect(request).toHaveBeenCalledOnce();
    expect(request.mock.calls[0]?.[1]?.headers).toMatchObject({ "x-palisade-proof": "synthetic-proof" });
  });
});
