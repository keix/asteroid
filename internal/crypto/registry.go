package crypto

// Registry provides access to all supported cryptographic algorithms
type Registry struct {
	generators map[string]Generator
	signers    map[string]Signer
}

// NewRegistry creates a new registry with all supported algorithms
func NewRegistry() *Registry {
	return &Registry{
		generators: map[string]Generator{
			"RS256": RS256Generator{},
			"ES256": ES256Generator{},
			"PS256": PS256Generator{},
		},
		signers: map[string]Signer{
			"RS256": RS256Signer{},
			"ES256": ES256Signer{},
			"PS256": PS256Signer{},
		},
	}
}

// GetGenerator returns the generator for the specified algorithm
func (r *Registry) GetGenerator(algorithm string) (Generator, bool) {
	gen, exists := r.generators[algorithm]
	return gen, exists
}

// GetSigner returns the signer for the specified algorithm
func (r *Registry) GetSigner(algorithm string) (Signer, bool) {
	signer, exists := r.signers[algorithm]
	return signer, exists
}

// SupportedAlgorithms returns a list of all supported algorithms
func (r *Registry) SupportedAlgorithms() []string {
	var algorithms []string
	for alg := range r.generators {
		algorithms = append(algorithms, alg)
	}
	return algorithms
}
