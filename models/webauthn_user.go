package models

import (
	"bytes"
	"github.com/go-webauthn/webauthn/webauthn"
)

type CredentialsStruct struct {
	Data []webauthn.Credential `json:"credentials"`
}

type WebAuthnUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
	icon        string
}

func (w *WebAuthnUser) getCredentialsStruct() (c *CredentialsStruct) {
	return &CredentialsStruct{Data: w.credentials}
}

func (w *WebAuthnUser) SetId(id []byte) {
	w.id = id
}

func (w *WebAuthnUser) SetName(name string) {
	w.name = name
}

func (w *WebAuthnUser) SetDisplayName(displayName string) {
	w.displayName = displayName
}

func (w *WebAuthnUser) SetCredentials(credentials []webauthn.Credential) {
	w.credentials = credentials
}

func (w *WebAuthnUser) SetIcon(icon string) {
	w.icon = icon
}

func (w WebAuthnUser) WebAuthnID() []byte {
	return w.id
}

func (w WebAuthnUser) WebAuthnName() string {
	return w.name
}

func (w WebAuthnUser) WebAuthnDisplayName() string {
	return w.displayName
}

func (w WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return w.credentials
}

func (w WebAuthnUser) WebAuthnIcon() string {
	return w.icon
}

func (w *WebAuthnUser) AddCredential(credential *webauthn.Credential) {
	w.credentials = append(w.credentials, *credential)
}

// naive implementation..
func (w *WebAuthnUser) UpdateCredential(credential *webauthn.Credential) {
	for i := range w.credentials {
		c := &w.credentials[i]
		if bytes.Equal(c.ID, credential.ID) {
			c = credential
			break
		}
	}
}
