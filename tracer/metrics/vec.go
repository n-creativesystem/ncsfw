package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	MApiLoginOAuth      prometheus.Counter
	MInstanceStart      prometheus.Counter
	MPageStatus         *prometheus.CounterVec
	MApiStatus          *prometheus.CounterVec
	MGRPCStatus         *prometheus.CounterVec
	MHttpRequestTotal   *prometheus.CounterVec
	MHttpRequestSummary *prometheus.SummaryVec

	ExporterName = "rbns"
)

func newCounterStartingAtZero(opts prometheus.CounterOpts, labelValues ...string) prometheus.Counter {
	counter := prometheus.NewCounter(opts)
	counter.Add(0)
	return counter
}

func newCounterVecStartingAtZero(opts prometheus.CounterOpts, labels []string, labelValues ...string) *prometheus.CounterVec {
	counter := prometheus.NewCounterVec(opts, labels)

	for _, label := range labelValues {
		counter.WithLabelValues(label).Add(0)
	}

	return counter
}

func initMetrics() {
	httpStatusCodes := []string{"200", "400", "404", "500", "unknown"}
	objectiveMap := map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001}
	MInstanceStart = prometheus.NewCounter(prometheus.CounterOpts{
		Name:      "instance_start_total",
		Help:      "counter for started instances",
		Namespace: ExporterName,
	})
	MPageStatus = newCounterVecStartingAtZero(
		prometheus.CounterOpts{
			Name:      "page_response_status_total",
			Help:      "page http response status",
			Namespace: ExporterName,
		}, []string{"code"}, httpStatusCodes...)
	MApiStatus = newCounterVecStartingAtZero(
		prometheus.CounterOpts{
			Name:      "api_response_status_total",
			Help:      "api http response status",
			Namespace: ExporterName,
		}, []string{"code"}, httpStatusCodes...)
	MGRPCStatus = newCounterVecStartingAtZero(
		prometheus.CounterOpts{
			Name:      "grpc_response_status_total",
			Help:      "api http response status",
			Namespace: ExporterName,
		}, []string{"code"}, httpStatusCodes...)
	MApiLoginOAuth = newCounterStartingAtZero(prometheus.CounterOpts{
		Name:      "api_login_oauth_total",
		Help:      "api login oauth counter",
		Namespace: ExporterName,
	})
	MHttpRequestTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_request_total",
			Help: "http request counter",
		},
		[]string{"handler", "statuscode", "method"},
	)
	MHttpRequestSummary = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "http_request_duration_milliseconds",
			Help:       "http request summary",
			Objectives: objectiveMap,
		},
		[]string{"handler", "statuscode", "method"},
	)
	prometheus.MustRegister(
		MInstanceStart,
		MPageStatus,
		MApiStatus,
		MGRPCStatus,
		MApiLoginOAuth,
		MHttpRequestTotal,
		MHttpRequestSummary,
	)
}
