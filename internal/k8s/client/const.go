// Copyright 2026 the xfx1-dns authors. SPDX-License-Identifier: AGPL-3.0-only

package client

import "fmt"

const (
	headerAccept        = "Accept"
	headerAuthorization = "Authorization"
	headerContentType   = "Content-Type"
	headerContinue      = "Continue"

	headerValueContentTypeApplyPatchYaml = "application/apply-patch+yaml"
	headerValueAcceptJson                = "application/json"

	urlParamContinue = "continue"
)

func headerValueBearer(token string) string {
	return fmt.Sprintf("Bearer %s", token)
}
