package report

import (
	"bytes"
	"io"
	"text/template"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/go-cvss/cvsserr"
)

func getTempleteString(r io.Reader) (string, error) {
	if r == nil {
		return "", errs.Wrap(cvsserr.ErrInvalidTemplate)
	}
	tmpdata := &bytes.Buffer{}
	if _, err := io.Copy(tmpdata, r); err != nil {
		return "", errs.Wrap(cvsserr.ErrInvalidTemplate, errs.WithCause(err))
	}
	return tmpdata.String(), nil
}

func executeTemplate(data interface{}, tempStr string) (io.Reader, error) {
	t, err := template.New("Repost").Parse(tempStr)
	if err != nil {
		return nil, errs.Wrap(cvsserr.ErrInvalidTemplate, errs.WithCause(err), errs.WithContext("templete", tempStr))
	}
	buf := &bytes.Buffer{}
	if err := t.Execute(buf, data); err != nil {
		return nil, errs.Wrap(cvsserr.ErrInvalidTemplate, errs.WithCause(err), errs.WithContext("templete", tempStr))
	}
	return buf, nil
}

/* Copyright 2018-2020 Spiegel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
