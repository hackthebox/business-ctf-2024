package database

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() {
	database, err := gorm.Open(sqlite.Open("permnotes.db"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	DB = database
	DB.AutoMigrate(&Role{}, &User{}, &Faction{}, &OIDCConfig{}, &Note{}, &Ban{})
}
func PrepareDatabase() {
	user := &Role{
		Name:  "user",
		Level: USER_LEVEL,
	}
	support := &Role{
		Name:  "support",
		Level: SUPPORT_LEVEL,
	}
	admin := &Role{
		Name:  "admin",
		Level: ADMIN_LEVEL,
	}
	DB.Create([]*Role{user, support, admin})
	wo := CreateNewFaction("WO", "West Oceania")
	ns := CreateNewFaction("NS", "Northern Scandinavia")
	ca := CreateNewFaction("CA", "Central Africa")
	CreateNewOIDCConfig(
		os.Getenv("WO_CLIENT_ID"),
		os.Getenv("WO_CLIENT_SECRET"),
		"https://wo.htb/idp",
		wo.ID,
	)
	CreateNewOIDCConfig(
		os.Getenv("NS_CLIENT_ID"),
		os.Getenv("NS_CLIENT_SECRET"),
		"https://ns.htb/idp",
		ns.ID,
	)
	CreateNewOIDCConfig(
		os.Getenv("CA_CLIENT_ID"),
		os.Getenv("CA_CLIENT_SECRET"),
		"https://ca.htb/idp",
		ca.ID,
	)
	CreateNewUser("support@wo.htb", *support, wo.ID)
	adminUser := CreateNewUser(os.Getenv("WO_ADMIN_EMAIL"), *admin, wo.ID)
	CreateNewUser("toby@wo.htb", *user, wo.ID)
	CreateNewUser("jack@ns.htb", *user, ns.ID)
	CreateNewUser("jessica@ns.htb", *user, ns.ID)
	CreateNewUser("tom@ca.htb", *user, ca.ID)
	DB.Create(&Ban{Email: "tom@ca.htb"})
	adminId := uint64(adminUser.ID)
	noteContent := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`[{"type":"p","attr":{},"content":"%s\n"}]`, os.Getenv("FLAG"))))
	CreateNote("My Secret", noteContent, true, &adminId)
	CreateNote(
		"Our plan for domination",
		"W3sidHlwZSI6InAiLCJhdHRyIjp7fSwiY29udGVudCI6IkFsdGhvdWdoIG91ciBtYW55IHRyZWF0aWVzIGZvcmJpZCB1cyBmcm9tIGV2ZXIgdXNpbmcgbnVjbGVhciB3ZWFwb25zIGFnYWluLCB3ZSBoYXZlIHVuZm9ydHVuYXRlbHkgZGV0ZWN0ZWQgYSBzcGlrZSBpbiByYWRpYXRpb24gY29taW5nIGZyb20gTm9ydGhlcm4gU2NhbmRpbmF2aWEsIHRoZXJlZm9yZSB3ZSBhcmUgZm9yY2VkIHRvIGFjdCBmaXJzdC5cbiJ9LHsidHlwZSI6InAiLCJhdHRyIjp7InN0eWxlIjoiZm9udC13ZWlnaHQ6NzAwIn0sImNvbnRlbnQiOiJXZSBzaGFsbCBib21iIGV2ZXJ5IHN1cGVycG93ZXIgb24gdGhpcyBwbGFuZXQgYW5kIGVzdGFibGlzaCBvdXIgZG9taW5hdGlvbiFcbiJ9XQ==",
		false,
		&adminId,
	)
	CreateNote(
		"Suspicious activity",
		"W3sidHlwZSI6InAiLCJhdHRyIjp7fSwiY29udGVudCI6Ikp1c3Qgc2F3IG9uZSBvZiB0aGVzZSBkcml2aW5nIGRvd24gbXkgc3RyZWV0Li4uIGFueWJvZHkga25vdyB3aGF0IGl0IGlzPyJ9LHsidHlwZSI6ImltZyIsImF0dHIiOnsic3JjIjoiaHR0cHM6Ly91cGxvYWQud2lraW1lZGlhLm9yZy93aWtpcGVkaWEvY29tbW9ucy90aHVtYi80LzRlLzE5LTAzLTIwMTItUGFyYWRlLXJlaGVhcnNhbF8tX1RvcG9sLU0uanBnLzEyMDBweC0xOS0wMy0yMDEyLVBhcmFkZS1yZWhlYXJzYWxfLV9Ub3BvbC1NLmpwZyIsInN0eWxlIjoid2lkdGg6NTAlO2hlaWd0aDphdXRvIn19XQ==",
		false,
		nil,
	)
	CreateNote(
		"Robbery in my shop!",
		"W3sidHlwZSI6InAiLCJhdHRyIjp7fSwiY29udGVudCI6IlRoZXJlIHdhcyBhIHJvYmJlcnkgaW4gbXkgc2hvcCB0aGUgb3RoZXIgZGF5IGFuZCB0aGV5IHN0b2xlIGV2ZXJ5dGhpbmchIFBsZWFzZSB0byBzdXBwb3J0IG1lIGdvIGNoZWNrIG91dCBvdXIgb25saW5lIHN0b3JlOlxuIn0seyJ0eXBlIjoiYSIsImF0dHIiOnsiaHJlZiI6Imh0dHA6Ly9mdW5reXN0b3JlLmh0YiJ9LCJjb250ZW50IjoiT25saW5lIFN0b3JlIn1d",
		false,
		nil,
	)
}
