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
	"io"
	"log/syslog"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/rs/zerolog"
)

const (
	SyslogFacility     = syslog.LOG_DAEMON
	SyslogDefaultLevel = syslog.LOG_INFO
)

type writerFilter struct {
	writer io.Writer
	level  int32
}

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

func messageFormatter(msg interface{}) string {
	if msg == nil {
		return ""
	}
	return color.New(color.BgBlue).Sprint(msg)
}

func init() {
	zerolog.TimeFieldFormat = time.StampMilli
	cw := zerolog.NewConsoleWriter()
	cw.TimeFormat = time.StampMilli
	cw.FormatMessage = messageFormatter
	stderrWriter = &writerFilter{
		writer: cw,
		level:  int32(zerolog.Disabled),
	}
	sl, err := syslog.New(SyslogFacility|SyslogDefaultLevel, "")
	if err == nil {
		syslogWriter = &writerFilter{
			writer: zerolog.SyslogLevelWriter(sl),
			level:  int32(zerolog.Disabled),
		}
	} else {
		defer Logger.Err(err).Msg("Unable to connect to syslog")
	}
	mw := zerolog.MultiLevelWriter(stderrWriter, syslogWriter)
	Logger = Instance(zerolog.New(mw).Hook(timestampHook))
}

func Instance(logger zerolog.Logger) LoggerInstance {
	return LoggerInstance{logger}
}

func (wf *writerFilter) Write(p []byte) (int, error) {
	if wf == nil || atomic.LoadInt32(&wf.level) >= int32(zerolog.Disabled) {
		return len(p), nil
	}
	return wf.writer.Write(p)
}

func (wf *writerFilter) WriteLevel(l zerolog.Level, p []byte) (int, error) {
	if wf == nil || int32(l) < atomic.LoadInt32(&wf.level) {
		return len(p), nil
	}
	if lw, ok := wf.writer.(zerolog.LevelWriter); ok {
		return lw.WriteLevel(l, p)
	}
	return wf.writer.Write(p)
}

func (wf *writerFilter) setLevel(level string) error {
	l, err := zerolog.ParseLevel(level)
	if err == nil {
		atomic.StoreInt32(&wf.level, int32(l))
	}
	return err
}

func SetStderrLevel(level string) error {
	return stderrWriter.setLevel(level)
}

func SetSyslogLevel(level string) error {
	return syslogWriter.setLevel(level)
}
