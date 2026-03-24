/** X.509 SVID response from the attestation endpoint. */
export interface X509SVIDResponse {
  spiffe_id: string;
  certificate: string;
  private_key: string;
  bundle: string;
  expires_at: string;
}

/** JWT SVID response from the attestation endpoint. */
export interface JWTSVIDResponse {
  spiffe_id: string;
  token: string;
  expires_at: string;
}

/** Trust bundle response. */
export interface BundleResponse {
  trust_domain: string;
  x509_authorities: string[];
  jwt_authorities: JWTAuthority[];
}

/** A single JWT authority within a bundle. */
export interface JWTAuthority {
  key_id: string;
  public_key: string;
}

/** SVID validation response. */
export interface ValidateResponse {
  valid: boolean;
  spiffe_id?: string;
  reason?: string;
  expires_at?: string;
}

/** Error body returned by the server on non-OK responses. */
export interface ErrorResponse {
  error: {
    code: string;
    message: string;
  };
}
