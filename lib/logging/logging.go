/*
Copyright © 2021 Mike Joseph <mike@mjoseph.org>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package logging

import (
	"time"

	"github.com/rs/zerolog"
)

const timeFormat = time.StampMilli

type LoggerInstance struct {
	zerolog.Logger
}

var (
	Logger       LoggerInstance
	stderrWriter *writerFilter
	syslogWriter *writerFilter
)

var timestampHook = zerolog.HookFunc(func(e *zerolog.Event, _ zerolog.Level, _ string) {
	e.Timestamp()
})

func init() {
	zerolog.TimeFieldFormat = timeFormat
	cw, err := newConsoleWriter()
	if err == nil {
		stderrWriter = cw
	} else {
		defer Logger.Err(err).Msg("Unable to setup console logger")
	}
	sw, err := newSyslogWriter()
	if err == nil {
		syslogWriter = sw
	} else {
		defer Logger.Err(err).Msg("Unable to connect to syslog")
	}
	mw := zerolog.MultiLevelWriter(stderrWriter, syslogWriter)
	Logger = Instance(zerolog.New(mw).Hook(timestampHook))
}

func Instance(logger zerolog.Logger) LoggerInstance {
	return LoggerInstance{logger}
}

func SetStderrLevel(level string) error {
	return stderrWriter.SetLevel(level)
}

func SetSyslogLevel(level string) error {
	return syslogWriter.SetLevel(level)
}
