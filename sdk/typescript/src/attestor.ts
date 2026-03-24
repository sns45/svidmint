/** Attestor gathers platform specific evidence for workload attestation. */
export interface Attestor {
  /** Returns the evidence type identifier (e.g. "aws_iid", "cf_access", "github_oidc"). */
  evidenceType(): string;

  /** Gathers platform specific evidence and returns it as a string (typically base64 or JWT). */
  gatherEvidence(): Promise<string>;
}
