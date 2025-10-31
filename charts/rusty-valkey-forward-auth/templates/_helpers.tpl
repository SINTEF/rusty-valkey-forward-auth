{{/*
Expand the name of the chart.
*/}}
{{- define "rusty-valkey-forward-auth.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "rusty-valkey-forward-auth.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "rusty-valkey-forward-auth.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "rusty-valkey-forward-auth.labels" -}}
helm.sh/chart: {{ include "rusty-valkey-forward-auth.chart" . }}
{{ include "rusty-valkey-forward-auth.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "rusty-valkey-forward-auth.selectorLabels" -}}
app.kubernetes.io/name: {{ include "rusty-valkey-forward-auth.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "rusty-valkey-forward-auth.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "rusty-valkey-forward-auth.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Resolve the managed secret name for configuration values.
*/}}
{{- define "rusty-valkey-forward-auth.secretName" -}}
{{- printf "%s-config" (include "rusty-valkey-forward-auth.fullname" .) }}
{{- end }}

{{/*
Derive the Valkey fullname as rendered by the dependent chart so we can build defaults.
*/}}
{{- define "rusty-valkey-forward-auth.valkeyFullname" -}}
{{- $valkey := .Values.valkey | default dict }}
{{- if $valkey.fullnameOverride }}
{{- $valkey.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default "valkey" $valkey.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Produce the default Valkey connection URL when the user has not provided one.
*/}}
{{- define "rusty-valkey-forward-auth.defaultValkeyURL" -}}
{{- $valkey := .Values.valkey | default dict }}
{{- if not $valkey.enabled }}
{{- "" }}
{{- else }}
{{- $service := $valkey.service | default dict }}
{{- $port := default 6379 $service.port }}
{{- printf "redis://%s:%v/0" (include "rusty-valkey-forward-auth.valkeyFullname" .) $port }}
{{- end }}
{{- end }}

{{/*
Assemble environment variables for the workload from values.config.
Secret references take precedence over literal values when both are provided.
*/}}
{{- define "rusty-valkey-forward-auth.env" -}}
{{- $root := . }}
{{- $cfg := .Values.config | default dict }}
{{- $targetPort := int (default 8080 .Values.service.targetPort) }}
{{- $port := $cfg.port }}
{{- if or $port (ne $targetPort 8080) }}
- name: PORT
  value: {{ printf "%v" (default $targetPort $port) | quote }}
{{- end }}
- name: ADDRESS
  value: "0.0.0.0"
{{- $valkey := $cfg.valkey | default dict }}
{{- $valkeyURL := tpl (default "" $valkey.url) $root | trim }}
{{- if not $valkeyURL }}
  {{- $fallbackValkeyURL := include "rusty-valkey-forward-auth.defaultValkeyURL" $root | trim }}
  {{- if $fallbackValkeyURL }}
    {{- $valkeyURL = $fallbackValkeyURL }}
  {{- end }}
{{- end }}
{{- if $valkeyURL }}
- name: VALKEY_URL
  value: {{ $valkeyURL | quote }}
{{- end }}
{{- $valkeyUser := tpl (default "" $valkey.username) $root | trim }}
{{- $valkeyUsernameSecret := $valkey.usernameSecret | default dict }}
{{- $valkeyUsernameSecretName := tpl (default "" $valkeyUsernameSecret.name) $root | trim }}
{{- $valkeyUsernameSecretKey := tpl (default "" $valkeyUsernameSecret.key) $root | trim }}
{{- if and $valkeyUsernameSecretName $valkeyUsernameSecretKey }}
- name: VALKEY_USERNAME
  valueFrom:
    secretKeyRef:
      name: {{ $valkeyUsernameSecretName }}
      key: {{ $valkeyUsernameSecretKey }}
{{- else if $valkeyUser }}
- name: VALKEY_USERNAME
  valueFrom:
    secretKeyRef:
      name: {{ include "rusty-valkey-forward-auth.secretName" $root }}
      key: valkey-username
{{- end }}
{{- $valkeyPasswordSecret := $valkey.passwordSecret | default dict }}
{{- $valkeyPasswordSecretName := tpl (default "" $valkeyPasswordSecret.name) $root | trim }}
{{- $valkeyPasswordSecretKey := tpl (default "" $valkeyPasswordSecret.key) $root | trim }}
{{- if and $valkeyPasswordSecretName $valkeyPasswordSecretKey }}
- name: VALKEY_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ $valkeyPasswordSecretName }}
      key: {{ $valkeyPasswordSecretKey }}
{{- else }}
  {{- $valkeyPassword := tpl (default "" $valkey.password) $root | trim }}
  {{- if $valkeyPassword }}
- name: VALKEY_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "rusty-valkey-forward-auth.secretName" $root }}
      key: valkey-password
  {{- end }}
{{- end }}
{{- $tokenSaltSecret := $cfg.tokenSaltSecret | default dict }}
{{- $tokenSaltSecretName := tpl (default "" $tokenSaltSecret.name) $root | trim }}
{{- $tokenSaltSecretKey := tpl (default "" $tokenSaltSecret.key) $root | trim }}
{{- if and $tokenSaltSecretName $tokenSaltSecretKey }}
- name: TOKEN_SALT
  valueFrom:
    secretKeyRef:
      name: {{ $tokenSaltSecretName }}
      key: {{ $tokenSaltSecretKey }}
{{- else }}
  {{- $tokenSalt := tpl (default "" $cfg.tokenSalt) $root | trim }}
  {{- if $tokenSalt }}
- name: TOKEN_SALT
  valueFrom:
    secretKeyRef:
      name: {{ include "rusty-valkey-forward-auth.secretName" $root }}
      key: token-salt
  {{- end }}
{{- end }}
{{- $cors := $cfg.cors | default dict }}
{{- if $cors.enabled }}
- name: CORS_ENABLED
  value: "true"
{{- end }}
{{- $allowOrigins := $cors.allowOrigins | default (list) }}
{{- $processedOrigins := list }}
{{- range $origin := $allowOrigins }}
  {{- $trimmedOrigin := tpl $origin $root | trim }}
  {{- if $trimmedOrigin }}
    {{- $processedOrigins = append $processedOrigins $trimmedOrigin }}
  {{- end }}
{{- end }}
{{- if gt (len $processedOrigins) 0 }}
- name: CORS_ALLOW_ORIGINS
  value: {{ join "," $processedOrigins | quote }}
{{- end }}
{{- $oauth := $cfg.oauth | default dict }}
{{- $issuer := tpl (default "" $oauth.issuerUrl) $root | trim }}
{{- if $issuer }}
- name: OAUTH_ISSUER_URL
  value: {{ $issuer | quote }}
{{- end }}
{{- $jwks := tpl (default "" $oauth.jwksUrl) $root | trim }}
{{- if $jwks }}
- name: OAUTH_JWKS_URL
  value: {{ $jwks | quote }}
{{- end }}
{{- $tenant := tpl (default "" $oauth.tenantId) $root | trim }}
{{- if $tenant }}
- name: OAUTH_TENANT_ID
  value: {{ $tenant | quote }}
{{- end }}
{{- if $oauth.jwksRefreshIntervalSecs }}
- name: OAUTH_JWKS_REFRESH_SECS
  value: {{ printf "%v" $oauth.jwksRefreshIntervalSecs | quote }}
{{- end }}
{{- $claims := $oauth.claims | default dict }}
{{- $subjectClaim := tpl (default "" $claims.subject) $root | trim }}
{{- if $subjectClaim }}
- name: OAUTH_SUBJECT_CLAIM
  value: {{ $subjectClaim | quote }}
{{- end }}
{{- $groupsClaim := tpl (default "" $claims.groups) $root | trim }}
{{- if $groupsClaim }}
- name: OAUTH_GROUPS_CLAIM
  value: {{ $groupsClaim | quote }}
{{- end }}
{{- $admin := $oauth.admin | default dict }}
{{- $adminGroup := tpl (default "admin" $admin.group) $root | trim }}
{{- if $adminGroup }}
- name: OAUTH_ADMIN_GROUP
  value: {{ $adminGroup | quote }}
{{- end }}
{{- if $admin.groupCaseSensitive }}
- name: OAUTH_ADMIN_CASE_SENSITIVE
  value: "true"
{{- end }}
{{- $frontend := $cfg.frontend | default dict }}
{{- $frontendAppName := tpl (default "" $frontend.appName) $root | trim }}
{{- if $frontendAppName }}
- name: FRONTEND_APP_NAME
  value: {{ $frontendAppName | quote }}
{{- end }}
{{- $frontendAuthority := tpl (default "" $frontend.oidcAuthority) $root | trim }}
{{- if $frontendAuthority }}
- name: FRONTEND_OIDC_AUTHORITY
  value: {{ $frontendAuthority | quote }}
{{- end }}
{{- $frontendClientID := tpl (default "" $frontend.oidcClientId) $root | trim }}
{{- if $frontendClientID }}
- name: FRONTEND_OIDC_CLIENT_ID
  value: {{ $frontendClientID | quote }}
{{- end }}
{{- $frontendRedirect := tpl (default "" $frontend.oidcRedirectUri) $root | trim }}
{{- if $frontendRedirect }}
- name: FRONTEND_OIDC_REDIRECT_URI
  value: {{ $frontendRedirect | quote }}
{{- end }}
{{- if .Values.settingsToml }}
- name: CONFIG_FILE
  value: /config/settings.toml
{{- end }}
{{- end }}
