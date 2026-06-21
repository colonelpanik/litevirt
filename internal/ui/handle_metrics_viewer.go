package ui

import (
	"bufio"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// handleMetricsViewer renders /metrics-viewer — a built-in dashboard
// that scrapes the local Prometheus exporter and groups counters/gauges
// by family. Operators who don't run Prometheus + Grafana still get a
// usable view of cluster health. "embedded dashboards".
func (s *Server) handleMetricsViewer(w http.ResponseWriter, r *http.Request) {
	data := s.pageData("Metrics", "metrics-viewer")
	families, err := scrapeMetrics(r.Context(), "http://127.0.0.1:7444/metrics")
	if err != nil {
		data["Error"] = err.Error()
		s.renderPage(w, "metrics_viewer.html", data)
		return
	}
	data["Families"] = families
	data["ScrapedAt"] = time.Now().UTC().Format(time.RFC3339)
	s.renderPage(w, "metrics_viewer.html", data)
}

// metricFamily is one Prometheus metric name and the (labels, value)
// samples we want to show.
type metricFamily struct {
	Name    string
	Help    string
	Type    string
	Samples []metricSample
}

type metricSample struct {
	Labels string // pre-formatted "k=v,k=v" — fine for a read-only view
	Value  float64
}

func scrapeMetrics(_ any, url string) ([]metricFamily, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("scrape %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scrape %s: %s", url, resp.Status)
	}

	byName := map[string]*metricFamily{}
	ensure := func(name string) *metricFamily {
		if f, ok := byName[name]; ok {
			return f
		}
		f := &metricFamily{Name: name}
		byName[name] = f
		return f
	}

	scan := bufio.NewScanner(resp.Body)
	scan.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scan.Scan() {
		line := scan.Text()
		switch {
		case strings.HasPrefix(line, "# HELP "):
			parts := strings.SplitN(strings.TrimPrefix(line, "# HELP "), " ", 2)
			if len(parts) == 2 {
				ensure(parts[0]).Help = parts[1]
			}
		case strings.HasPrefix(line, "# TYPE "):
			parts := strings.SplitN(strings.TrimPrefix(line, "# TYPE "), " ", 2)
			if len(parts) == 2 {
				ensure(parts[0]).Type = parts[1]
			}
		case strings.HasPrefix(line, "#"):
			continue
		case line == "":
			continue
		default:
			name, labels, value, ok := parseSample(line)
			if !ok {
				continue
			}
			f := ensure(name)
			f.Samples = append(f.Samples, metricSample{Labels: labels, Value: value})
		}
	}
	if err := scan.Err(); err != nil {
		return nil, err
	}

	out := make([]metricFamily, 0, len(byName))
	for _, f := range byName {
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// parseSample splits one Prometheus text-format line into name, labels
// (pre-formatted), and value. Histograms etc. fall through with their
// raw `_bucket{...}` name preserved.
func parseSample(line string) (name, labels string, value float64, ok bool) {
	// `metric_name{k="v",...} 1.23` or `metric_name 1.23`
	openBrace := strings.IndexByte(line, '{')
	spaceIdx := strings.IndexByte(line, ' ')
	if spaceIdx < 0 {
		return "", "", 0, false
	}
	if openBrace > 0 && openBrace < spaceIdx {
		closeBrace := strings.IndexByte(line, '}')
		if closeBrace < 0 || closeBrace > spaceIdx {
			return "", "", 0, false
		}
		name = line[:openBrace]
		labels = line[openBrace+1 : closeBrace]
	} else {
		name = line[:spaceIdx]
	}
	rest := strings.TrimSpace(line[spaceIdx+1:])
	// drop a trailing timestamp if present
	if i := strings.IndexByte(rest, ' '); i > 0 {
		rest = rest[:i]
	}
	if _, scanErr := fmt.Sscan(rest, &value); scanErr != nil {
		return "", "", 0, false
	}
	return name, labels, value, true
}
