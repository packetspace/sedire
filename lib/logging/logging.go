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
	"bytes"
	"fmt"
	"io"
	"log/syslog"
	"os"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/rs/zerolog"
)

const (
	SyslogFacility     = syslog.LOG_DAEMON
	SyslogDefaultLevel = syslog.LOG_INFO
	fmtMarker          = "\f"
)

type writerFilter struct {
	writer io.Writer
	level  int32
}

type logFormatter struct {
	writer io.Writer
	cw     zerolog.ConsoleWriter
	buf    bytes.Buffer
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

func consoleMessageFormatter(msg interface{}) string {
	if msg == nil {
		return ""
	}
	return color.New(color.BgBlue).Sprint(msg)
}

func logMessageFormatter(msg interface{}) string {
	if msg == nil {
		return ""
	}
	return fmt.Sprint(msg, fmtMarker)
}

func init() {
	zerolog.TimeFieldFormat = time.StampMilli
	cw := zerolog.NewConsoleWriter()
	cw.Out = os.Stderr
	cw.TimeFormat = time.StampMilli
	cw.FormatMessage = consoleMessageFormatter
	stderrWriter = &writerFilter{
		writer: cw,
		level:  int32(zerolog.Disabled),
	}
	sl, err := syslog.New(SyslogFacility|SyslogDefaultLevel, "")
	lf := newLogFormatter(zerolog.SyslogLevelWriter(sl))
	if err == nil {
		syslogWriter = &writerFilter{
			writer: lf,
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

func newLogFormatter(w io.Writer) *logFormatter {
	var lf logFormatter
	lf.writer = w
	lf.cw = zerolog.NewConsoleWriter()
	lf.cw.Out = &lf.buf
	lf.cw.NoColor = true
	lf.cw.PartsOrder = []string{zerolog.MessageFieldName}
	lf.cw.FormatMessage = logMessageFormatter
	return &lf
}

func (lf *logFormatter) formatEvent(p []byte) (b []byte, n int, err error) {
	lf.buf.Reset()
	n, err = lf.cw.Write(p)
	parts := bytes.SplitN(lf.buf.Bytes(), []byte(fmtMarker), 1)
	var newBuf bytes.Buffer
	newBuf.Write(bytes.TrimSpace(parts[0]))
	if len(parts) > 1 {
		newBuf.WriteRune(' ')
		newBuf.WriteRune('(')
		newBuf.Write(bytes.TrimSpace(parts[1]))
		newBuf.WriteRune(')')
	}
	b = newBuf.Bytes()
	return
}

func (lf *logFormatter) Write(p []byte) (int, error) {
	b, n, err := lf.formatEvent(p)
	if err != nil {
		return 0, err
	}
	_, err = lf.writer.Write(b)
	return n, err
}

func (lf *logFormatter) WriteLevel(l zerolog.Level, p []byte) (int, error) {
	b, n, err := lf.formatEvent(p)
	if err != nil {
		return 0, err
	}
	if lw, ok := lf.writer.(zerolog.LevelWriter); ok {
		_, err = lw.WriteLevel(l, b)
	} else {
		_, err = lf.writer.Write(b)
	}
	return n, err
}

func SetStderrLevel(level string) error {
	return stderrWriter.setLevel(level)
}

func SetSyslogLevel(level string) error {
	return syslogWriter.setLevel(level)
}
