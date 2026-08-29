// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { PalisadeSensor, type SensorBatch } from "./index";

afterEach(() => {
  vi.useRealTimers();
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
      proofProvider: async (action) => action === "events" ? "synthetic-proof" : "wrong-proof",
    });
    sensor.start();
    await sensor.flush(true);
    sensor.stop();

    expect(sendBeacon).not.toHaveBeenCalled();
    expect(request).toHaveBeenCalledOnce();
    expect(request.mock.calls[0]?.[1]?.headers).toMatchObject({ "x-palisade-proof": "synthetic-proof" });
  });

  it("flushes every fifteen seconds by default", async () => {
    vi.useFakeTimers();
    const request = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 202 }));
    const sensor = new PalisadeSensor({ endpoint: "/events", fetchImpl: request });
    sensor.start();
    await vi.advanceTimersByTimeAsync(14_999);
    expect(request).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(request).toHaveBeenCalledOnce();
    sensor.stop();
    vi.useRealTimers();
  });

  it("rejects a flush interval that can consume the origin rate-limit budget", () => {
    expect(() => new PalisadeSensor({ endpoint: "/events", flushIntervalMs: 2_000 })).toThrow(/bounds/);
  });

  it("rejects endpoints that could export sensor events cross-origin", () => {
    for (const endpoint of [
      "https://collector.example/events",
      "//collector.example/events",
      "/events?tenant=private",
      "/events#fragment",
      "/events\nnext",
    ]) {
      expect(() => new PalisadeSensor({ endpoint })).toThrow(/same-origin/);
    }
  });

  it("bounds the queue without creating immediate flush bursts", async () => {
    const request = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 202 }));
    const sensor = new PalisadeSensor({ endpoint: "/events", maxBatchSize: 2, maxQueueSize: 4, fetchImpl: request });
    sensor.start();
    for (let index = 0; index < 20; index += 1) document.dispatchEvent(new Event("visibilitychange"));
    expect(request).not.toHaveBeenCalled();
    await sensor.flush();
    await sensor.flush();
    await sensor.flush();
    sensor.stop();
    expect(request).toHaveBeenCalledTimes(2);
    for (const call of request.mock.calls) {
      const payload = JSON.parse(String(call[1]?.body)) as SensorBatch;
      expect(payload.events).toHaveLength(2);
    }
  });
});
