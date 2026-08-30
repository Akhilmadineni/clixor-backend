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

	LegacyTransitionMessages = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "clustr", Subsystem: "messaging", Name: "transition_messages_total",
		Help: "Accepted production-05b transition messages whose payload is not end-to-end encrypted.",
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

	MediaCleanup = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "clustr", Subsystem: "media", Name: "pending_cleanup_total",
		Help: "Expired media reservations and cleanup failures.",
	}, []string{"result"})

	PushFailures = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "clustr", Subsystem: "push", Name: "failures_total",
		Help: "Push notification delivery failures.",
	})

	PushDeliveries = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "clustr", Subsystem: "push", Name: "deliveries_total",
		Help: "Durable push delivery lifecycle outcomes.",
	}, []string{"result"})

	PushDeliveryFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "clustr", Subsystem: "push", Name: "delivery_failures_total",
		Help: "Durable push delivery failures by bounded, token-free class.",
	}, []string{"class"})

	PushDeliveryLag = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "clustr", Subsystem: "push", Name: "delivery_lag_seconds",
		Help:    "Time from durable push creation to APNs acceptance.",
		Buckets: []float64{0.25, 0.5, 1, 2, 5, 10, 30, 60, 300, 900, 3600},
	})

	MailDeliveries = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "clustr", Subsystem: "mail", Name: "deliveries_total",
		Help: "Encrypted durable mail delivery lifecycle outcomes.",
	}, []string{"result"})

	MailDeliveryFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "clustr", Subsystem: "mail", Name: "delivery_failures_total",
		Help: "Mail delivery failures by bounded payload-free class.",
	}, []string{"class"})

	MailDeliveryLag = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "clustr", Subsystem: "mail", Name: "delivery_lag_seconds",
		Help:    "Time from encrypted queue creation to SMTP acceptance.",
		Buckets: []float64{0.25, 0.5, 1, 2, 5, 10, 30, 60, 300, 900, 3600},
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
