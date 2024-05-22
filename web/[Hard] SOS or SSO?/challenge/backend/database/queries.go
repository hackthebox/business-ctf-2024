package database

import "log"

func CreateNewFaction(name, region string) *Faction {
	faction := &Faction{
		Name:   name,
		Region: region,
	}
	DB.Create(faction)
	return faction
}

func CreateNewOIDCConfig(clientId, clientSecret, endpoint string, factionId uint64) *OIDCConfig {
	config := &OIDCConfig{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Endpoint:     endpoint,
		FactionID:    factionId,
	}
	DB.Create(config)
	return config
}

func UpdateOIDCConfig(config *OIDCConfig) {
	tx := DB.Save(config)
	if tx.Error != nil {
		log.Println(tx.Error)
	}
}

func FindOIDCConfigWithFaction(factionId uint64) *OIDCConfig {
	var config OIDCConfig
	tx := DB.First(&config, "faction_id = ?", factionId)
	if tx.Error != nil {
		log.Println(tx.Error)
		return nil
	}
	return &config
}

func FindUserWithEmail(email string) *User {
	var user User
	tx := DB.Preload("Role").First(&user, "email = ?", email)
	if tx.Error != nil {
		log.Println(tx.Error)
		return nil
	}
	return &user
}

func FindUserWithId(id int) *User {
	var user User
	tx := DB.Preload("Role").Preload("Faction").First(&user, id)
	if tx.Error != nil {
		log.Println(tx.Error)
		return nil
	}
	return &user
}

func FindFactionWithId(id int) *Faction {
	var faction Faction
	tx := DB.First(&faction, id)
	if tx.Error != nil {
		log.Println(tx.Error)
		return nil
	}
	return &faction
}

func CreateNewUser(email string, role Role, factionId uint64) *User {
	user := &User{
		Email:     email,
		RoleID:    role.ID,
		Role:      role,
		FactionID: factionId,
	}
	DB.Create(user)
	return user
}

func FindRoleWithName(name string) *Role {
	var role Role
	tx := DB.First(&role, "name = ?", name)
	if tx.Error != nil {
		log.Println(tx.Error)
		return nil
	}
	return &role
}

func CreateNote(title, content string, private bool, authorId *uint64) *Note {
	note := &Note{
		Title:    title,
		Content:  content,
		Private:  private,
		AuthorID: authorId,
	}
	DB.Create(note)
	return note
}

func GetUserPrivateNotes(authorId uint64) []Note {
	notes := []Note{}
	tx := DB.Preload("Author").Where("author_id = ? AND private = 1", authorId).Find(&notes)
	if tx.Error != nil {
		log.Println(tx.Error)
	}
	return notes
}

func GetFactionNotes(factionId uint64) []Note {
	notes := []Note{}
	tx := DB.InnerJoins("Author", DB.Where(User{FactionID: factionId})).Where("private = 0").Find(&notes)
	if tx.Error != nil {
		log.Println(tx.Error)
	}
	return notes
}

func GetAnonymousNotes() []Note {
	notes := []Note{}
	tx := DB.Where("author_id IS NULL AND private = 0").Find(&notes)
	if tx.Error != nil {
		log.Println(tx.Error)
	}
	return notes
}

func FindNoteWithId(id int) *Note {
	var note Note
	tx := DB.Preload("Author").First(&note, id)
	if tx.Error != nil {
		log.Println(tx.Error)
		return nil
	}
	return &note
}

func UpdateNoteContent(note *Note, content string) {
	note.Content = content
	tx := DB.Save(note)
	if tx.Error != nil {
		log.Println(tx.Error)
	}
}

func DeleteNote(note *Note) {
	tx := DB.Delete(note)
	if tx.Error != nil {
		log.Println(tx.Error)
	}
}

func GetUsers() []User {
	users := []User{}
	tx := DB.Preload("Faction").Preload("Role").Find(&users)
	if tx.Error != nil {
		log.Println(tx.Error)
	}
	return users
}

func GetOIDCConfigs() []OIDCConfig {
	configs := []OIDCConfig{}
	tx := DB.Preload("Faction").Find(&configs)
	if tx.Error != nil {
		log.Println(tx.Error)
	}
	return configs
}

func BanEmail(email string) {
	ban := &Ban{
		Email: email,
	}
	tx := DB.Save(ban)
	if tx.Error != nil {
		log.Println(tx.Error)
	}
}

func DeleteUser(user *User) {
	tx := DB.Delete(user)
	if tx.Error != nil {
		log.Println(tx.Error)
	}
}

func GetBan(email string) *Ban {
	var ban Ban
	tx := DB.First(&ban, email)
	if tx.Error != nil {
		log.Println(tx.Error)
		return nil
	}
	return &ban
}
