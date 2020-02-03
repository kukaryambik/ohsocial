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
	ID         int
	Login      string
	Password   string
	Fullname   string
	BIO        string
	Created    string
	LastUpdate string
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

		user := getUserFromLogin(cookieUser)

		db := dbCon(dbURL)
		defer db.Close()

		t := template.Must(template.ParseFiles("index.html"))
		t.Execute(w, user)
	}
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if _, ok := checkCookie(r); ok {
		http.Redirect(w, r, "/", 301)
	}

	if r.Method == "GET" {
		t := template.Must(template.ParseFiles("auth.html"))
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
		t := template.Must(template.ParseFiles("new.html"))
		t.Execute(w, nil)
	} else {
		user := User{
			Login:    r.PostForm["login"][0],
			Password: shaStr(r.PostForm["password"][0] + r.PostForm["login"][0]),
			Fullname: strings.Join(r.PostForm["fullname"], " "),
			BIO:      strings.Join(r.PostForm["bio"], " "),
		}

		db := dbCon(dbURL)
		defer db.Close()

		if m, _ := regexp.MatchString(`^[a-z0-9][a-z0-9_-]*[a-z0-9]$`, user.Login); !m {
			http.Redirect(w, r, "/new#alert", 301)
		}

		if rowExists(db, `select * from userList where login = ?`, user.Login) {
			http.Redirect(w, r, "/new#alert", 301)
		} else {
			insert, err := db.Query(
				"insert into userList (login, password, fullname, BIO) values (?, ?, ?, ?)",
				user.Login,
				user.Password,
				user.Fullname,
				user.BIO,
			)
			// if there is an error inserting, handle it
			if err != nil {
				log.Println(err.Error())
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

		user := getUserFromLogin(cookieUser)

		db := dbCon(dbURL)
		defer db.Close()

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
				select ID, fullname, BIO, created
				from userList where ID != ?
				and (fullname like '%`+search+`%' or login like '%`+search+`%')
				order by created desc limit 10
				`, user.ID)
			if err != nil && err != sql.ErrNoRows {
				log.Println(err.Error())
			}

			for query.Next() {
				var inDB User
				if err := query.Scan(&inDB.ID, &inDB.Fullname, &inDB.BIO, &inDB.Created); err != nil {
					log.Println(err)
					continue
				}
				data.UserList = append(data.UserList, inDB)
			}

			defer query.Close()

			t := template.Must(template.ParseFiles("users.html"))
			t.Execute(w, data)
		} else {

			var data User

			data.ID, _ = strconv.Atoi(params.Get("id"))

			if data.ID == user.ID {
				http.Redirect(w, r, "/", 301)
			}

			if rowExists(db, `select * from userList where ID = ?`, data.ID) {
				data = getUserFromID(data.ID)
			}

			t := template.Must(template.ParseFiles("user.html"))
			t.Execute(w, data)
		}
	}
}

func chatsHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if cookieUser, ok := checkCookie(r); !ok {
		http.Redirect(w, r, "/auth", 301)
	} else {

		user := getUserFromLogin(cookieUser)

		db := dbCon(dbURL)
		defer db.Close()

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
				ChatID int
				Chat   []msg
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
							m.User = getUserFromID(u).Fullname
						}
						data.Chat = append(data.Chat, m)
					}

					defer query.Close()
				}

				t := template.Must(template.ParseFiles("chat.html"))
				t.Execute(w, data)
			} else {
				http.Redirect(w, r, "/chats", 301)
			}
		} else {

			type chatMeta struct {
				ID   string
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
						var chatMembers []string
						queryMembersID, err := db.Query(`
						select userID
						from chatUser
						where chatID = ? and userID != ?
					`, chat.ID, user.ID)
						if err != nil && err != sql.ErrNoRows {
							log.Println(err.Error())
						}
						for queryMembersID.Next() {
							var userID int
							if err := queryMembersID.Scan(&userID); err != nil {
								log.Println(err)
								continue
							}
							tmpUser := getUserFromID(userID)
							chatMembers = append(chatMembers, tmpUser.Fullname)
						}
						chat.Name = strings.Join(chatMembers, ",")
						defer queryMembersID.Close()
					}
					data.Chats = append(data.Chats, chat)
				}

				defer query.Close()
			}

			t := template.Must(template.ParseFiles("chats.html"))
			t.Execute(w, data)
		}
	}
}

func editHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if cookieUser, ok := checkCookie(r); !ok {
		http.Redirect(w, r, "/auth", 301)
	} else {

		user := getUserFromLogin(cookieUser)

		db := dbCon(dbURL)
		defer db.Close()

		if r.Method == "GET" {
			t := template.Must(template.ParseFiles("edit.html"))
			t.Execute(w, user)
		} else {
			if r.PostForm["password"][0] != "" {
				if _, err := db.Exec(
					"update userList set password = ? where ID = ?",
					shaStr(r.PostForm["password"][0]+user.Login), user.ID,
				); err != nil {
					log.Println(err.Error())
				}
			}
			if r.PostForm["fullname"][0] != "" {
				if _, err := db.Exec(
					"update userList set fullname = ? where ID = ?",
					r.PostForm["fullname"][0], user.ID,
				); err != nil {
					log.Println(err.Error())
				}
			}
			if r.PostForm["bio"][0] != "" {
				if _, err := db.Exec(
					"update userList set BIO = ? where ID = ?",
					r.PostForm["bio"][0], user.ID,
				); err != nil {
					log.Println(err.Error())
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

func getUserFromID(id int) User {

	var user User
	user.ID = id

	db := dbCon(dbURL)
	defer db.Close()

	querry := db.QueryRow(`select login, fullname, BIO, created from userList where id = ?`, id)

	if err := querry.Scan(
		&user.Login, &user.Fullname, &user.BIO, &user.Created,
	); err != nil && err != sql.ErrNoRows {
		log.Println(err.Error())
	}
	return user

}

func getUserFromLogin(login string) User {

	var user User
	user.Login = login

	db := dbCon(dbURL)
	defer db.Close()

	querry := db.QueryRow(`select ID, fullname, BIO, created from userList where login = ?`, login)

	if err := querry.Scan(
		&user.ID, &user.Fullname, &user.BIO, &user.Created,
	); err != nil && err != sql.ErrNoRows {
		log.Println(err.Error())
	}
	return user

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
