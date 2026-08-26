export type SensorEventKind = "pointer" | "scroll" | "visibility" | "navigation" | "performance";

export interface SensorEvent {
  sequence: number;
  elapsedBucketMs: number;
  kind: SensorEventKind;
  valueBucket: number;
}

export interface SensorBatch {
  sessionId: string;
  sensorVersion: string;
  events: SensorEvent[];
}

export interface SensorOptions {
  endpoint: string;
  sessionId: string;
  flushIntervalMs?: number;
  maxBatchSize?: number;
  fetchImpl?: typeof fetch;
  proofProvider?: () => Promise<string>;
}

const SENSOR_VERSION = "0.1.0";
const TIME_BUCKET_MS = 25;
const VALUE_BUCKET = 16;

function bucket(value: number, size: number): number {
  return Math.max(0, Math.round(value / size) * size);
}

export class PalisadeSensor {
  readonly #options: Required<Pick<SensorOptions, "flushIntervalMs" | "maxBatchSize">> & SensorOptions;
  readonly #startedAt = performance.now();
  readonly #queue: SensorEvent[] = [];
  #sequence = 0;
  #timer: ReturnType<typeof setInterval> | undefined;
  #lastPointerAt = 0;
  #lastScrollAt = 0;
  #abort: AbortController | undefined;

  constructor(options: SensorOptions) {
    if (!options.endpoint || !options.sessionId) throw new Error("endpoint and sessionId are required");
    this.#options = { flushIntervalMs: 2_000, maxBatchSize: 32, ...options };
  }

  start(): this {
    if (this.#abort) return this;
    this.#abort = new AbortController();
    const signal = this.#abort.signal;
    addEventListener("pointermove", this.#onPointer, { passive: true, signal });
    addEventListener("scroll", this.#onScroll, { passive: true, signal });
    document.addEventListener("visibilitychange", this.#onVisibility, { passive: true, signal });
    addEventListener("pagehide", this.#onPageHide, { passive: true, signal });
    this.#record("navigation", bucket(performance.getEntriesByType("navigation").length, 1));
    this.#timer = setInterval(() => void this.flush(), this.#options.flushIntervalMs);
    return this;
  }

  stop(): void {
    this.#abort?.abort();
    this.#abort = undefined;
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = undefined;
    void this.flush();
  }

  async flush(useBeacon = false): Promise<void> {
    if (this.#queue.length === 0) return;
    const events = this.#queue.splice(0, this.#options.maxBatchSize);
    const payload: SensorBatch = { sessionId: this.#options.sessionId, sensorVersion: SENSOR_VERSION, events };
    const body = JSON.stringify(payload);
    if (useBeacon && navigator.sendBeacon?.(this.#options.endpoint, new Blob([body], { type: "application/json" }))) return;
    const request = this.#options.fetchImpl ?? fetch;
    try {
      const proof = await this.#options.proofProvider?.();
      const response = await request(this.#options.endpoint, {
        method: "POST",
        headers: { "content-type": "application/json", ...(proof ? { "x-palisade-proof": proof } : {}) },
        body,
        keepalive: true,
        credentials: "same-origin",
      });
      if (!response.ok) this.#queue.unshift(...events);
    } catch {
      this.#queue.unshift(...events);
    }
  }

  #record(kind: SensorEventKind, valueBucket: number): void {
    this.#queue.push({
      sequence: ++this.#sequence,
      elapsedBucketMs: bucket(performance.now() - this.#startedAt, TIME_BUCKET_MS),
      kind,
      valueBucket,
    });
    if (this.#queue.length >= this.#options.maxBatchSize) void this.flush();
  }

  #onPointer = (event: PointerEvent): void => {
    const now = performance.now();
    if (now - this.#lastPointerAt < 100) return;
    this.#lastPointerAt = now;
    const movement = Math.hypot(event.movementX, event.movementY);
    this.#record("pointer", bucket(Math.min(movement, 512), VALUE_BUCKET));
  };

  #onScroll = (): void => {
    const now = performance.now();
    if (now - this.#lastScrollAt < 150) return;
    this.#lastScrollAt = now;
    this.#record("scroll", bucket(Math.min(Math.abs(scrollY), 4096), 64));
  };

  #onVisibility = (): void => this.#record("visibility", document.hidden ? 0 : 1);
  #onPageHide = (): void => { void this.flush(true); };
}

export function createSensor(options: SensorOptions): PalisadeSensor {
  return new PalisadeSensor(options);
}
