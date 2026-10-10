package estategraph

import "strings"

func hasLayerPrefix(appLayers, baseLayers []LayerObservation) bool {
	if len(appLayers) == 0 || len(baseLayers) == 0 || len(appLayers) < len(baseLayers) {
		return false
	}
	for i := range baseLayers {
		if appLayers[i].Digest != baseLayers[i].Digest {
			return false
		}
	}
	return true
}

func digestOnly(value string) string {
	if value == "" {
		return ""
	}
	if i := strings.LastIndex(value, "@"); i >= 0 {
		return value[i+1:]
	}
	if i := strings.LastIndex(value, "sha256:"); i >= 0 {
		return value[i:]
	}
	return value
}
