import type { ProofLayer } from "../proof_layer.js";
import type {
  JsonObject,
  JsonValue,
  OtelSpan,
  ProofLayerResult,
  ToolEvent
} from "../types.js";
import { eventsToOtelSpans } from "./instrumentation.js";

export interface ProofLayerExporterCaptureOptions {
  provider: string;
  model: string;
  input: JsonValue | JsonObject;
  output: JsonValue | JsonObject;
  systemId?: string;
  requestId?: string;
  threadId?: string | null;
  userRef?: string | null;
  modelParameters?: JsonValue;
  retrievalCommitment?: string | null;
  toolOutputsCommitment?: string | null;
  redactions?: string[];
  encryptionEnabled?: boolean;
  traceId?: string;
  system?: string;
}

export class ProofLayerExporter {
  readonly proofLayer: ProofLayer;

  constructor(proofLayer: ProofLayer) {
    this.proofLayer = proofLayer;
  }

  async captureToolEvents(
    events: ToolEvent[],
    options: ProofLayerExporterCaptureOptions
  ): Promise<ProofLayerResult> {
    const spans = eventsToOtelSpans(events, {
      traceId: options.traceId,
      system: options.system
    });
    return this.captureSpans(spans, options, { tool_events: events });
  }

  async captureSpans(
    spans: OtelSpan[],
    options: ProofLayerExporterCaptureOptions,
    extraTrace: JsonObject = {}
  ): Promise<ProofLayerResult> {
    return this.proofLayer.capture({
      provider: options.provider,
      model: options.model,
      input: options.input,
      output: options.output,
      systemId: options.systemId,
      requestId: options.requestId,
      threadId: options.threadId,
      userRef: options.userRef,
      modelParameters: options.modelParameters,
      retrievalCommitment: options.retrievalCommitment,
      toolOutputsCommitment: options.toolOutputsCommitment,
      trace: {
        spans,
        ...extraTrace
      },
      otelSemconvVersion: "1.0.0",
      redactions: options.redactions,
      encryptionEnabled: options.encryptionEnabled
    });
  }
}
