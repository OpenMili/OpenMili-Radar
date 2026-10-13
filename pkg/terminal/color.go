package terminal

func paint(value string, tone Tone, enabled bool) string {
	if !enabled {
		return value
	}
	code := ""
	switch tone {
	case ToneSuccess:
		code = "\x1b[1;32m"
	case ToneBlocked:
		code = "\x1b[1;31m"
	case ToneWarning:
		code = "\x1b[1;33m"
	case ToneInfo:
		code = "\x1b[1;36m"
	default:
		return value
	}
	// Use an explicit reset so output is stable across terminals and platforms;
	// the renderer owns its wire format.
	return code + value + "\x1b[0m"
}
