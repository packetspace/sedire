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

	"github.com/rs/zerolog"
)

const (
	fmtMarker = "\f"
)

type logFormatter struct {
	writer io.Writer
}

func logMessageFormatter(msg interface{}) string {
	if msg == nil {
		return ""
	}
	return fmt.Sprint(msg, fmtMarker)
}

func newLogFormatter(w io.Writer) *logFormatter {
	return &logFormatter{writer: w}
}

func (lf *logFormatter) formatEvent(p []byte) (b []byte, n int, err error) {
	var cwBuf, lfBuf bytes.Buffer
	cw := zerolog.NewConsoleWriter()
	cw.Out = &cwBuf
	cw.NoColor = true
	cw.PartsOrder = []string{zerolog.MessageFieldName}
	cw.FormatMessage = logMessageFormatter
	n, err = cw.Write(p)
	parts := bytes.SplitN(cwBuf.Bytes(), []byte(fmtMarker), 2)
	lfBuf.Write(bytes.TrimSpace(parts[0]))
	if len(parts) == 2 {
		lfBuf.WriteRune(' ')
		lfBuf.WriteRune('(')
		lfBuf.Write(bytes.TrimSpace(parts[1]))
		lfBuf.WriteRune(')')
	}
	b = lfBuf.Bytes()
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
