export type SensorEventKind = "pointer" | "scroll" | "visibility" | "navigation" | "performance";

export interface SensorEvent {
  sequence: number;
  elapsedBucketMs: number;
  kind: SensorEventKind;
  valueBucket: number;
}

export interface SensorBatch {
  sessionId?: string;
  sensorVersion: string;
  events: SensorEvent[];
}

export interface SensorOptions {
  endpoint: string;
  sessionId?: string;
  flushIntervalMs?: number;
  maxBatchSize?: number;
  maxQueueSize?: number;
  fetchImpl?: typeof fetch;
  proofProvider?: (action: "events") => Promise<string>;
}

const SENSOR_VERSION = "0.2.0";
const TIME_BUCKET_MS = 25;
const VALUE_BUCKET = 16;

function validSameOriginEndpoint(value: string): boolean {
  return value.length >= 2 && value.length <= 256 && value.startsWith("/") && !value.startsWith("//") &&
    !/[?#\\\u0000-\u001f\u007f]/u.test(value);
}

function bucket(value: number, size: number): number {
  return Math.max(0, Math.round(value / size) * size);
}

export class PalisadeSensor {
  readonly #options: Required<Pick<SensorOptions, "flushIntervalMs" | "maxBatchSize" | "maxQueueSize">> & SensorOptions;
  readonly #startedAt = performance.now();
  readonly #queue: SensorEvent[] = [];
  #sequence = 0;
  #timer: ReturnType<typeof setInterval> | undefined;
  #lastPointerAt = 0;
  #lastScrollAt = 0;
  #abort: AbortController | undefined;
  #inFlight: Promise<void> | undefined;

  constructor(options: SensorOptions) {
    if (!validSameOriginEndpoint(options.endpoint)) throw new Error("endpoint must be a bounded same-origin path without query or fragment");
    this.#options = { flushIntervalMs: 15_000, maxBatchSize: 64, maxQueueSize: 256, ...options };
    if (!Number.isInteger(this.#options.flushIntervalMs) || this.#options.flushIntervalMs < 15_000 || this.#options.flushIntervalMs > 300_000 ||
      !Number.isInteger(this.#options.maxBatchSize) || this.#options.maxBatchSize < 1 || this.#options.maxBatchSize > 64 ||
      !Number.isInteger(this.#options.maxQueueSize) || this.#options.maxQueueSize < this.#options.maxBatchSize || this.#options.maxQueueSize > 1_024) {
      throw new Error("invalid sensor flush or queue bounds");
    }
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
    if (this.#inFlight) {
      await this.#inFlight;
      return;
    }
    const operation = this.#flushOnce(useBeacon);
    this.#inFlight = operation;
    try {
      await operation;
    } finally {
      if (this.#inFlight === operation) this.#inFlight = undefined;
    }
  }

  async #flushOnce(useBeacon: boolean): Promise<void> {
    if (this.#queue.length === 0) return;
    const events = this.#queue.splice(0, this.#options.maxBatchSize);
    const payload: SensorBatch = {
      ...(this.#options.sessionId ? { sessionId: this.#options.sessionId } : {}),
      sensorVersion: SENSOR_VERSION,
      events,
    };
    const body = JSON.stringify(payload);
    // sendBeacon cannot attach the one-time proof header required in production.
    // When a proof provider exists, keepalive fetch is the only valid transport.
    if (useBeacon && !this.#options.proofProvider && navigator.sendBeacon?.(this.#options.endpoint, new Blob([body], { type: "application/json" }))) return;
    const request = this.#options.fetchImpl ?? fetch;
    try {
      const proof = await this.#options.proofProvider?.("events");
      const response = await request(this.#options.endpoint, {
        method: "POST",
        headers: { "content-type": "application/json", ...(proof ? { "x-palisade-proof": proof } : {}) },
        body,
        keepalive: true,
        credentials: "same-origin",
      });
      if (!response.ok) this.#restore(events);
    } catch {
      this.#restore(events);
    }
  }

  #restore(events: SensorEvent[]): void {
    this.#queue.unshift(...events);
    if (this.#queue.length > this.#options.maxQueueSize) this.#queue.length = this.#options.maxQueueSize;
  }

  #record(kind: SensorEventKind, valueBucket: number): void {
    const sequence = ++this.#sequence;
    if (this.#queue.length >= this.#options.maxQueueSize) return;
    this.#queue.push({
      sequence,
      elapsedBucketMs: bucket(performance.now() - this.#startedAt, TIME_BUCKET_MS),
      kind,
      valueBucket,
    });
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
