package util

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"example.com/permnotes/auth"
	"example.com/permnotes/database"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

func VisitAndExamineNote(noteId int) {
	token, err := auth.GenerateToken(database.FindUserWithEmail("support@wo.htb"), 1800)
	if err != nil {
		log.Println("Could not get token for support user:", err.Error())
		return
	}
	bannedWords := []string{"nuclear", "fusion", "fission", "bomb", "missile", "fallout"}
	ctx, cancel := chromedp.NewContext(
		context.Background(),
	)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	var content string
	scanContent := chromedp.ActionFunc(func(ctx context.Context) error {
		for _, word := range bannedWords {
			if strings.Contains(content, word) {
				var nodes []*cdp.Node
				err := chromedp.Nodes("/html/body/div/div[2]/div/div[3]/div[2]", &nodes, chromedp.AtLeast(0)).Do(ctx)
				if err != nil || len(nodes) == 0 {
					break
				}
				return chromedp.MouseClickNode(nodes[0]).Do(ctx)
			}
		}
		return nil
	})
	err = chromedp.Run(ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			expr := cdp.TimeSinceEpoch(time.Now().Add(1800 * time.Second))
			err := network.SetCookie("notesToken", token).
				WithExpires(&expr).
				WithDomain("localhost").
				WithPath("/").
				WithHTTPOnly(true).
				WithSecure(false).
				Do(ctx)
			if err != nil {
				log.Println(err.Error())
				return err
			}
			return nil
		}),
		chromedp.Navigate(fmt.Sprintf("http://localhost:8080/app/note/%d", noteId)),
		chromedp.Text("body", &content),
		scanContent,
	)
	if err != nil {
		log.Fatal(err)
	}
}
