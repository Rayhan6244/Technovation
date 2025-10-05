# Traffic Bondhu Server

Node.js + Express backend with SQLite for handling public (user) and police portal authentication.

## Features
- User & Police signup (hashed passwords with bcrypt)
- User & Police login (session-based auth using express-session + SQLite store)
- SQLite database (`traffic_bondhu.sqlite`) auto-initialized
- Static serving of existing HTML pages
- Simple REST endpoints under `/api`

## Endpoints
- `POST /api/signup/user` { full_name, dob, nid, license, address, email, phone, password }
- `POST /api/signup/police` { full_name, police_id, nid, email, phone, password }
- `POST /api/login/user` { phone, license, password }
- `POST /api/login/police` { police_id, password }
- `GET /api/me` -> current session user
- `POST /api/logout`

Responses: `{ success: boolean, message?, user? }`

## Project Structure
```
server.js
package.json
db.js
traffic_bondhu.sqlite (created at runtime)
sessions.sqlite (session store)
/public (user portal pages)
/police portal (police portal pages)
SignIn.html
SignUp.html
Landing.html
```

## Setup

1. Install Node.js (v18+ recommended).
2. In project root create `.env`:
```
PORT=3000
SESSION_SECRET=your_long_random_secret
```
3. Install dependencies:
```
npm install
```
4. Run in development (auto-restart):
```
npm run dev
```
Or production mode:
```
npm start
```

Visit: `http://localhost:3000/SignUp.html` or `http://localhost:3000/SignIn.html`

## Data Files
- `traffic_bondhu.sqlite` stores users, police_officers, violations.
- `sessions.sqlite` stores session data.

Delete these files to reset data (while server stopped).

## Extending
- Add new tables in `db.js`.
- Add protected routes by checking `req.session.user`.
- Differentiate dashboards based on `role`.

## Simple Protection Example
```
app.get('/api/secure-data', (req,res)=>{
  if(!req.session.user) return res.status(401).json({success:false,message:'Auth required'});
  res.json({success:true,data:'Secret for '+req.session.user.full_name});
});
```

## Notes
- Current HTML pages are static—logic added only for signup/login via fetch.
- For production deploy behind HTTPS and change session cookie settings (secure, sameSite, etc.).
- Add input validation & rate limiting before public launch.

## License
Internal hackathon prototype.
