package auth

import (
	"encoding/base64"
	"unsafe"

	"github.com/google/uuid"
)

func Uuid() string {
	return uuid.New().String() // strings.ReplaceAll(u1.String(), "-", ""), nil
}

func EncodedUuid() string {
	uuid := uuid.New()
	b := (*[]byte)(unsafe.Pointer(&uuid))
	return base64.RawURLEncoding.EncodeToString(*b)
}

func DecodeUuid(id string) (*uuid.UUID, error) {
	dec, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		return nil, err
	}
	decID, err := uuid.FromBytes(dec)
	if err != nil {
		return nil, err
	}
	return &decID, nil
}
