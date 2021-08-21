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
	"sync/atomic"

	"github.com/rs/zerolog"
)

type writerFilter struct {
	writer io.Writer
	level  int32
}

func newWriterFilter(w io.Writer) *writerFilter {
	return &writerFilter{
		writer: w,
		level:  int32(zerolog.Disabled),
	}
}

func (wf *writerFilter) Write(p []byte) (int, error) {
	if wf == nil || wf.GetLevel() >= zerolog.Disabled {
		return len(p), nil
	}
	return wf.writer.Write(p)
}

func (wf *writerFilter) WriteLevel(l zerolog.Level, p []byte) (int, error) {
	if wf == nil || l < wf.GetLevel() {
		return len(p), nil
	}
	if lw, ok := wf.writer.(zerolog.LevelWriter); ok {
		return lw.WriteLevel(l, p)
	}
	return wf.writer.Write(p)
}

func (wf *writerFilter) SetLevel(level string) error {
	l, err := zerolog.ParseLevel(level)
	if err == nil {
		atomic.StoreInt32(&wf.level, int32(l))
	}
	return err
}

func (wf *writerFilter) GetLevel() zerolog.Level {
	return zerolog.Level(atomic.LoadInt32(&wf.level))
}
