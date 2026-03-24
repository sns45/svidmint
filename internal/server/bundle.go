package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/http"
)

type bundleResponse struct {
	TrustDomain     string              `json:"trust_domain"`
	X509Authorities []x509AuthorityResp `json:"x509_authorities"`
	JWTAuthorities  []jwtAuthorityResp  `json:"jwt_authorities"`
	RefreshHint     int                 `json:"refresh_hint"`
	SequenceNumber  int64               `json:"sequence_number"`
}

type x509AuthorityResp struct {
	ASN1 string `json:"asn1"`
}

type jwtAuthorityResp struct {
	KeyID     string            `json:"kid"`
	PublicKey map[string]string `json:"public_key"`
}

func (s *Server) handleBundle(w http.ResponseWriter, r *http.Request) {
	bundle, err := s.ca.GetBundle(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "bundle_error", err.Error())
		return
	}

	resp := bundleResponse{
		TrustDomain:     bundle.TrustDomain,
		X509Authorities: make([]x509AuthorityResp, 0, len(bundle.X509Authorities)),
		JWTAuthorities:  make([]jwtAuthorityResp, 0, len(bundle.JWTAuthorities)),
		RefreshHint:     300,
		SequenceNumber:  bundle.SequenceNumber,
	}

	for _, cert := range bundle.X509Authorities {
		resp.X509Authorities = append(resp.X509Authorities, x509AuthorityResp{
			ASN1: base64.StdEncoding.EncodeToString(cert.Raw),
		})
	}

	for _, auth := range bundle.JWTAuthorities {
		pubKey := encodePublicKey(auth.PublicKey)
		resp.JWTAuthorities = append(resp.JWTAuthorities, jwtAuthorityResp{
			KeyID:     auth.KeyID,
			PublicKey: pubKey,
		})
	}

	writeJSON(w, http.StatusOK, resp)
}

func encodePublicKey(key any) map[string]string {
	result := make(map[string]string)
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		result["kty"] = "EC"
		result["crv"] = k.Curve.Params().Name
		result["x"] = base64.RawURLEncoding.EncodeToString(k.X.Bytes())
		result["y"] = base64.RawURLEncoding.EncodeToString(k.Y.Bytes())
	case *rsa.PublicKey:
		result["kty"] = "RSA"
		result["n"] = base64.RawURLEncoding.EncodeToString(k.N.Bytes())
		result["e"] = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())
	}
	// For EC keys, normalize curve name
	if result["crv"] == elliptic.P256().Params().Name {
		result["crv"] = "P-256"
	}
	return result
}
