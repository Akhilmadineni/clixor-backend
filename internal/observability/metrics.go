package observability

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	HTTPRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "clustr", Subsystem: "http", Name: "requests_total",
		Help: "Total HTTP requests.",
	}, []string{"method", "route", "status"})

	HTTPDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "clustr", Subsystem: "http", Name: "request_duration_seconds",
		Help: "HTTP request duration.", Buckets: prometheus.DefBuckets,
	}, []string{"method", "route"})

	RateLimited = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "clustr", Subsystem: "http", Name: "rate_limited_total",
		Help: "Requests rejected by rate limits.",
	}, []string{"namespace"})

	WebsocketConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "clustr", Subsystem: "realtime", Name: "connections",
		Help: "Current authenticated WebSocket connections.",
	})

	OutboxEvents = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "clustr", Subsystem: "outbox", Name: "events_total",
		Help: "Transactional outbox processing outcomes.",
	}, []string{"result"})

	OutboxLag = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "clustr", Subsystem: "outbox", Name: "delivery_lag_seconds",
		Help:    "Time from durable event creation to realtime publication.",
		Buckets: []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60},
	})

	PushFailures = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "clustr", Subsystem: "push", Name: "failures_total",
		Help: "Push notification delivery failures.",
	})

	VerificationEvents = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "clustr", Subsystem: "verification", Name: "events_total",
		Help: "Phone verification lifecycle outcomes.",
	}, []string{"stage", "outcome"})

	VerificationDeliveryEvents = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "clustr", Subsystem: "verification", Name: "delivery_events_total",
		Help: "Signed SMS delivery outcomes reported by the transport provider.",
	}, []string{"status"})
)
