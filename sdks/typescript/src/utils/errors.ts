export class ProofLayerSdkError extends Error {
  readonly code: string;
  readonly details?: unknown;

  constructor(message: string, code = "proof_layer_error", details?: unknown) {
    super(message);
    this.name = "ProofLayerSdkError";
    this.code = code;
    this.details = details;
  }
}

export class ProofLayerHttpError extends ProofLayerSdkError {
  readonly status: number;
  readonly operation: string;

  constructor(operation: string, status: number, details?: unknown) {
    super(`${operation} failed (${status})`, "proof_layer_http_error", details);
    this.name = "ProofLayerHttpError";
    this.status = status;
    this.operation = operation;
  }
}
