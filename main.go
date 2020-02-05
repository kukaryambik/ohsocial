package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// User structure
type User struct {
	ID          int
	Login       string
	Password    string
	FirstName   string
	LastName    string
	Fullname    string
	DateOfBirth string
	Gender      string
	Interests   string
	Bio         string
	Location    string
	Created     string
	Updated     string
}

var (
	dbURL string
	port  string
	// Cookies is list of cookies
	Cookies map[string]string
)

func init() {
	dbURL = os.Getenv("DB_URL")
	if dbURL == "" {
		dbURL = "ohsocial:ohsocial@tcp(127.0.0.1:3306)/ohsocial"
	}

	port = os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	Cookies = make(map[string]string)
}

func main() {

	mux := http.NewServeMux()

	mux.HandleFunc("/", indexHandler) // set router
	mux.HandleFunc("/auth", authHandler)
	mux.HandleFunc("/new", newHandler)
	mux.HandleFunc("/edit", editHandler)
	mux.HandleFunc("/users", usersHandler)
	mux.HandleFunc("/chats", chatsHandler)
	mux.HandleFunc("/logout", logoutHandler)

	fs := http.FileServer(http.Dir("assets"))
	mux.Handle("/assets/", http.StripPrefix("/assets/", fs))

	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalln("ListenAndServe: ", err)
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if cookieUser, ok := checkCookie(r); !ok {
		http.Redirect(w, r, "/auth", 301)
	} else {

		db := dbCon(dbURL)
		defer db.Close()

		user := getUser(db, "login", cookieUser)

		t := template.Must(template.ParseFiles("html/index.html"))
		t.Execute(w, user)
	}
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if _, ok := checkCookie(r); ok {
		http.Redirect(w, r, "/", 301)
	}

	if r.Method == "GET" {
		t := template.Must(template.ParseFiles("html/auth.html"))
		t.Execute(w, nil)
	} else {
		user := User{
			Login:    r.PostForm["login"][0],
			Password: shaStr(r.PostForm["password"][0] + r.PostForm["login"][0]),
		}

		// Make a cookie
		cookie := shaStr(user.Login + strconv.FormatInt(time.Now().Unix(), 10))
		Cookies[cookie] = user.Login

		db := dbCon(dbURL)
		defer db.Close()

		if rowExists(db, `select login from userList where login = ? and password = ?`, user.Login, user.Password) {
			expire := time.Now().AddDate(0, 0, 3)
			oreo := http.Cookie{
				Name:     "Oreo",
				Value:    cookie,
				Expires:  expire,
				HttpOnly: true,
				Domain:   r.Host,
				//Secure:   true,
			}
			http.SetCookie(w, &oreo)
			http.Redirect(w, r, "/", 301)
		} else {
			http.Redirect(w, r, "/auth#alert", 301)
		}

	}
}

func newHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if _, ok := checkCookie(r); ok {
		http.Redirect(w, r, "/", 301)
	}

	if r.Method == "GET" {
		t := template.Must(template.ParseFiles("html/new.html"))
		t.Execute(w, nil)
	} else {
		f := r.PostForm
		user := User{
			Login:       f["login"][0],
			Password:    shaStr(f["password"][0] + f["login"][0]),
			FirstName:   f["firstname"][0],
			LastName:    f["lastname"][0],
			DateOfBirth: f["dateofbirth"][0],
			Gender:      f["gender"][0],
			Interests:   f["interests"][0],
			Bio:         f["bio"][0],
			Location:    f["location"][0],
		}

		db := dbCon(dbURL)
		defer db.Close()

		if m, _ := regexp.MatchString(`^[a-z0-9]+$`, user.Login); !m {
			http.Redirect(w, r, "/new#alert", 301)
			return
		}

		if rowExists(db, `select login from userList where login = ?`, user.Login) {
			http.Redirect(w, r, "/new#alert", 301)
		} else {
			insert, err := db.Query(
				`insert into userList
				(login, password, firstName, lastName, dateOfBirth, gender, interests, bio, location)
				values (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				user.Login,
				user.Password,
				user.FirstName,
				user.LastName,
				user.DateOfBirth,
				user.Gender,
				user.Interests,
				user.Bio,
				user.Location,
			)
			// if there is an error inserting, handle it
			if err != nil {
				log.Println(err)
			}
			// be careful deferring Queries if you are using transactions
			defer insert.Close()
		}

		http.Redirect(w, r, "/auth", 301)
	}
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if cookieUser, ok := checkCookie(r); !ok {
		http.Redirect(w, r, "/auth", 301)
	} else {

		db := dbCon(dbURL)
		defer db.Close()

		user := getUser(db, "login", cookieUser)

		u, err := url.Parse(r.URL.String())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal server error"))
			return
		}

		params := u.Query()

		if params.Get("id") == "" {
			type tmplData struct {
				UserList []User
			}

			var search string
			if params.Get("q") != "" {
				search = params.Get("q")
			}

			var data tmplData

			query, err := db.Query(`
				select ID, login, firstName, lastName, updated
				from userList
				where concat_ws(' ', login, firstName, lastName) like '%` + search + `%'
				order by updated desc limit 10
				`)
			if err != nil && err != sql.ErrNoRows {
				log.Println(err.Error())
			}

			for query.Next() {
				var inDB User
				if err := query.Scan(
					&inDB.ID, &inDB.Login, &inDB.FirstName, &inDB.LastName, &inDB.Updated,
				); err != nil {
					log.Println(err)
					continue
				}
				inDB.Fullname = userName(inDB)
				data.UserList = append(data.UserList, inDB)
			}

			defer query.Close()

			t := template.Must(template.ParseFiles("html/users.html"))
			t.Execute(w, data)
		} else {

			var data User

			data.ID, _ = strconv.Atoi(params.Get("id"))

			if data.ID == user.ID {
				http.Redirect(w, r, "/", 301)
			}

			if rowExists(db, `select login from userList where ID = ?`, data.ID) {
				data = getUser(db, "ID", data.ID)
			}

			t := template.Must(template.ParseFiles("html/user.html"))
			t.Execute(w, data)
		}
	}
}

func chatsHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if cookieUser, ok := checkCookie(r); !ok {
		http.Redirect(w, r, "/auth", 301)
	} else {

		db := dbCon(dbURL)
		defer db.Close()

		user := getUser(db, "login", cookieUser)

		u, err := url.Parse(r.URL.String())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal server error"))
			return
		}

		params := u.Query()
		if params.Get("id") != "" || params.Get("with") != "" {

			type msg struct {
				UserID int
				User   string
				Text   string
				Time   string
			}

			type tmplData struct {
				ChatName string
				ChatID   int
				Chat     []msg
			}

			var data tmplData
			var chatID int

			if params.Get("with") != "" {
				withUserID, err := strconv.Atoi(params.Get("with"))
				if err != nil {
					log.Println(err)
					http.Redirect(w, r, "/chats", 301)
				}
				queryStr := `
				select chatID from chatUser where chatID in ( 
					select chatID from (
						select chatID, (count(userID)) as countMembers
						from chatUser group by chatID
					) as q1
					where countMembers = 2 and chatID in (
						select chatID from chatUser where userID = ?
					)
				) and userID = ?`
				if rowExists(db, queryStr, user.ID, withUserID) {
					if err := db.QueryRow(queryStr, user.ID, withUserID).Scan(&chatID); err != nil {
						log.Println(err)
					}
				} else {
					var users = []int{user.ID, withUserID}
					chatID, err = createChat("", users)
					if err != nil {
						log.Println(err)
						http.Redirect(w, r, "/chats", 301)
					}
				}
			} else {
				chatID, err = strconv.Atoi(params.Get("id"))
				if err != nil {
					log.Println(err)
					http.Redirect(w, r, "/chats", 301)
				}
			}

			if rowExists(db, `select chatID from chatUser where userID = ? and chatID = ?`, user.ID, chatID) {
				if r.Method == "POST" {
					text := strings.Join(r.PostForm["msg"], " ")
					insert, err := db.Query(
						"insert into chats (chatID, userID, msg) values (?, ?, ?)",
						chatID,
						user.ID,
						text,
					)
					// if there is an error inserting, handle it
					if err != nil {
						log.Println(err.Error())
					}
					// be careful deferring Queries if you are using transactions
					defer insert.Close()
				}
				data.ChatID = chatID
				if rowExists(db, `select chatID from chats where chatID = ?`, chatID) {
					query, err := db.Query(`select userID, msg, created from chats where chatID = ? order by created`, chatID)
					if err != nil && err != sql.ErrNoRows {
						log.Println(err.Error())
					}
					defer query.Close()

					data.ChatName = getChat(db, chatID, user.ID)

					for query.Next() {
						var m msg
						var u int
						if err := query.Scan(&u, &m.Text, &m.Time); err != nil {
							log.Println(err)
							continue
						}
						m.UserID = u
						if u == user.ID {
							m.User = "Me"
						} else {
							m.User = getUser(db, "ID", u).Fullname
						}
						data.Chat = append(data.Chat, m)
					}
				}

				t := template.Must(template.ParseFiles("html/chat.html"))
				t.Execute(w, data)
			} else {
				http.Redirect(w, r, "/chats", 301)
			}
		} else {

			type chatMeta struct {
				ID   int
				Name string
			}

			type tmplData struct {
				Chats []chatMeta
			}
			var data tmplData

			if rowExists(db, `select chatID from chatUser where userID = ?`, user.ID) {
				query, err := db.Query(`
				select ID, name
				from chatList
				where ID in (
					select chatID
					from chatUser
					where userID = ?
				)
				`, user.ID)
				if err != nil && err != sql.ErrNoRows {
					log.Println(err.Error())
				}

				for query.Next() {
					var chat chatMeta
					if err := query.Scan(&chat.ID, &chat.Name); err != nil {
						log.Println(err)
						continue
					}

					if chat.Name == "" {
						chat.Name = getChat(db, chat.ID, user.ID)
					}
					data.Chats = append(data.Chats, chat)
				}

				defer query.Close()
			}

			t := template.Must(template.ParseFiles("html/chats.html"))
			t.Execute(w, data)
		}
	}
}

func editHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if cookieUser, ok := checkCookie(r); !ok {
		http.Redirect(w, r, "/auth", 301)
	} else {

		db := dbCon(dbURL)
		defer db.Close()

		user := getUser(db, "login", cookieUser)

		if r.Method == "GET" {
			t := template.Must(template.ParseFiles("html/edit.html"))
			t.Execute(w, user)
		} else if r.Method == "POST" {
			p := r.PostForm
			f := []string{"firstName", "lastName", "dateOfBirth", "gender", "interests", "bio", "location"}
			for _, i := range f {
				if p[strings.ToLower(i)][0] != "" {
					setUser(db, user, i, p[strings.ToLower(i)][0])
				}
			}

			http.Redirect(w, r, "/", 301)
		}
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if _, ok := checkCookie(r); !ok {
		http.Redirect(w, r, "/auth", 301)
	} else {
		oreo := http.Cookie{
			Name:     "Oreo",
			Value:    "",
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
			Domain:   r.Host,
			//Secure:   true,
		}
		http.SetCookie(w, &oreo)
		http.Redirect(w, r, "/", 301)
	}
}

func getChat(db *sql.DB, chatID, userID int) string {
	var name string
	err := db.QueryRow(`select name	from chatList where ID = ?`, chatID).Scan(&name)
	if err != nil && err != sql.ErrNoRows {
		log.Println(err.Error())
	}

	if name == "" {
		var chatMembers []string
		queryMembersID, err := db.Query(`
			select userID from chatUser
			where chatID = ? and userID != ?
		`, chatID, userID)
		if err != nil && err != sql.ErrNoRows {
			log.Println(err.Error())
		}
		defer queryMembersID.Close()
		for queryMembersID.Next() {
			var tmpUserID int
			if err := queryMembersID.Scan(&tmpUserID); err != nil {
				log.Println(err)
				continue
			}
			tmpUser := getUser(db, "ID", tmpUserID)
			chatMembers = append(chatMembers, tmpUser.Fullname)
		}
		var sep string
		if len(chatMembers) > 1 {
			sep = ", "
		}
		name = strings.Join(chatMembers, sep)
	}
	return name
}

func checkCookie(r *http.Request) (string, bool) {
	cookie, err := r.Cookie("Oreo")
	if err != nil {
		return "", false
	}
	if user, ok := Cookies[cookie.Value]; ok {
		return user, ok
	}
	return "", false
}

func setUser(db *sql.DB, user User, key, value string) {
	if _, err := db.Exec(
		`update userList set `+key+` = ? where ID = ?`, value, user.ID,
	); err != nil {
		log.Println(err.Error())
		return
	}
}

func userName(user User) string {
	var n string
	if user.FirstName+user.LastName != "" {
		n = fmt.Sprintf(`%s %s`, user.FirstName, user.LastName)
	} else {
		n = user.Login
	}
	return n
}

func getUser(db *sql.DB, from string, user interface{}) User {

	var u User

	querry := db.QueryRow(`
		select
			ID, login, firstName, lastName, dateOfBirth, gender, interests, bio, location, created
		from userList where `+from+` = ?
	`, user)

	if err := querry.Scan(
		&u.ID, &u.Login, &u.FirstName, &u.LastName, &u.DateOfBirth, &u.Gender, &u.Interests, &u.Bio, &u.Location, &u.Created,
	); err != nil && err != sql.ErrNoRows {
		log.Println(err.Error())
	}
	u.Fullname = userName(u)
	return u

}

func createChat(name string, users []int) (int, error) {
	var chatID int

	db := dbCon(dbURL)
	defer db.Close()

	if _, err := db.Exec(`insert into chatList (name) values (?)`, name); err != nil {
		return 0, err
	}

	if err := db.QueryRow(`select last_insert_id()`).Scan(&chatID); err != nil {
		return 0, err
	}

	for _, u := range users {
		if _, err := db.Exec(
			`insert into chatUser (chatID, userID) values (?, ?)`,
			chatID, u,
		); err != nil {
			return chatID, err
		}
	}

	return chatID, nil
}

// https://snippets.aktagon.com/snippets/756-checking-if-a-row-exists-in-go-database-sql-and-sqlx-
func rowExists(db *sql.DB, query string, args ...interface{}) bool {
	var exists bool
	query = fmt.Sprintf("select exists (%s)", query)
	if err := db.QueryRow(query, args...).Scan(&exists); err != nil && err != sql.ErrNoRows {
		log.Printf("error checking if row exists '%s' %v\n", args, err)
	}
	return exists
}

func shaStr(s string) string {
	sha := sha256.Sum256([]byte(s))
	str := hex.EncodeToString(sha[:])
	return str
}

// DBCon is db connection
func dbCon(url string) *sql.DB {
	db, err := sql.Open("mysql", url)
	if err != nil {
		log.Fatalln("SQL open error: ", err)
	}
	return db
}
