package web

import (
	"encoding/base64"
	"unsafe"

	"github.com/google/uuid"
	gonanoid "github.com/matoous/go-nanoid/v2"
)

func Uuid() string {
	return uuid.New().String() // strings.ReplaceAll(u1.String(), "-", ""), nil
}

func B64Uuid() string {
	uuid := uuid.New()
	b := (*[]byte)(unsafe.Pointer(&uuid))
	return base64.RawURLEncoding.EncodeToString(*b)
}

func DecodeB64Uuid(id string) (*uuid.UUID, error) {
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

func NanoId() string {
	// good enough for Planetscale https://planetscale.com/blog/why-we-chose-nanoids-for-planetscales-api
	id, err := gonanoid.Generate("0123456789abcdefghijklmnopqrstuvwxyz", 12)

	if err != nil {
		id = ""
	}

	return id
}

func IsValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}
