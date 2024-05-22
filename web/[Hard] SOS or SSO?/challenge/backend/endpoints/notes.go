package endpoints

import (
	"strconv"

	"example.com/permnotes/database"
	"example.com/permnotes/models"
	"example.com/permnotes/util"
	"github.com/gin-gonic/gin"
)

func noteToNoteModel(note *database.Note) models.NoteModel {
	var author string
	if note.Author == nil {
		author = "anonymous"
	} else {
		author = note.Author.Email
	}
	return models.NoteModel{
		ID:        note.ID,
		Title:     note.Title,
		Content:   note.Content,
		UpdatedAt: note.UpdatedAt,
		Author:    author,
		Private:   note.Private,
	}
}

func createNotesModels(notes []database.Note) []models.NoteModel {
	noteModels := []models.NoteModel{}
	for _, note := range notes {
		noteModels = append(noteModels, noteToNoteModel(&note))
	}

	return noteModels
}

func GetNotes(c *gin.Context) {
	// Private notes
	content := gin.H{
		"private":   []models.NoteModel{},
		"faction":   []models.NoteModel{},
		"anonymous": []models.NoteModel{},
	}
	userClaims := GetUserClaims(c)
	if userClaims != nil {
		content["private"] = createNotesModels(database.GetUserPrivateNotes(userClaims.UserID))
		content["faction"] = createNotesModels(database.GetFactionNotes(userClaims.FactionID))
	}
	content["anonymous"] = createNotesModels(database.GetAnonymousNotes())
	c.JSON(200, gin.H{"notes": content})
}

func GetNote(c *gin.Context) {
	note := getNoteFromUrl(c)
	if note == nil {
		return
	}
	c.JSON(200, noteToNoteModel(note))
}

func CreateNote(c *gin.Context) {
	var newNote models.NewNoteModel
	err := c.BindJSON(&newNote)
	if err != nil {
		c.JSON(400, gin.H{
			"message": "Invalid note!",
		})
		return
	}
	userClaims := GetUserClaims(c)
	var userId *uint64
	var private bool
	if userClaims != nil {
		userId = &userClaims.UserID
		private = newNote.Private
	} else {
		userId = nil
		private = false
	}
	c.JSON(200, gin.H{
		"id": database.CreateNote(
			newNote.Title,
			newNote.Content,
			private,
			userId,
		).ID,
	})
}

func UpdateNote(c *gin.Context) {
	note := getNoteFromUrl(c)
	if note == nil {
		return
	}
	var updatedContent models.UpdateContentModel
	err := c.BindJSON(&updatedContent)
	if err != nil {
		c.JSON(400, gin.H{
			"message": "Invalid note content!",
		})
		return
	}
	database.UpdateNoteContent(note, updatedContent.Content)
	c.JSON(204, gin.H{})
}

func RemoveNote(c *gin.Context) {
	if GetUserClaims(c) == nil {
		c.JSON(403, gin.H{
			"message": "You cannot hide your tracks now!",
		})
		return
	}
	note := getNoteFromUrl(c)
	if note == nil {
		return
	}
	database.DeleteNote(note)
	c.JSON(204, gin.H{})
}

func ReportNote(c *gin.Context) {
	note := getNoteFromUrl(c)
	if note == nil {
		return
	}
	go util.VisitAndExamineNote(int(note.ID))
	c.JSON(200, gin.H{
		"message": "Thanks, our team is taking a look at this note",
	})
}

func getNoteFromUrl(c *gin.Context) *database.Note {
	noteId, err := strconv.Atoi(c.Param("noteId"))
	if err != nil {
		c.JSON(404, gin.H{
			"message": "Note not found",
		})
		c.Abort()
		return nil
	}
	note := database.FindNoteWithId(noteId)
	if note == nil {
		c.JSON(404, gin.H{
			"message": "Note not found",
		})
		c.Abort()
		return nil
	}
	if !noteAccessControl(c, note) {
		c.JSON(403, gin.H{
			"message": "You do not have access to this note!",
		})
		c.Abort()
		return nil
	}
	return note
}

func noteAccessControl(c *gin.Context, note *database.Note) bool {
	userClaims := GetUserClaims(c)
	if note.AuthorID == nil {
		return true
	}
	if userClaims == nil {
		return note.Author == nil // Only public notes
	}
	if note.Private {
		return *note.AuthorID == userClaims.UserID
	}
	if userClaims.Level >= note.Author.Role.Level {
		return true
	}

	return note.Author.FactionID == userClaims.FactionID
}
