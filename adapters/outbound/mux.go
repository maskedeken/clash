package outbound

type Mux struct {
	Enabled     bool `proxy:"enabled,omitempty"`
	Concurrency int  `proxy:"concurrency,omitempty"`
	IdleTimeout int  `proxy:"idle,omitempty"` // in seconds
}
