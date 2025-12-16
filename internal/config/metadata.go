package config

import (
	"time"
)

type BuildInfo struct {
	name    string
	version string
	date    string
}

var DefaultVersion = "0.0.1"
var DefaultDate = time.Now().Format(time.RFC3339)

func NewBuildInfo(appname string, version string) BuildInfo {
	return BuildInfo{
		version: version,
		name:    appname,
		date:    DefaultDate,
	}
}

func (b BuildInfo) Name() string {
	return b.name
}

func (b BuildInfo) Version() string {
	return b.version
}
