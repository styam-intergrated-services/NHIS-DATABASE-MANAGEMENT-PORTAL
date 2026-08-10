
const express = require('express');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'CHANGE_THIS_IN_PRODUCTION';
const db = new Database(process.env.DB_FILE || 'nhis.db');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'Staff', active INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS members (
 id INTEGER PRIMARY KEY AUTOINCREMENT, member_no TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
 phone TEXT, plan TEXT, status TEXT DEFAULT 'Active', created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS providers (
 id INTEGER PRIMARY KEY AUTOINCREMENT, provider_no TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
 type TEXT, status TEXT DEFAULT 'Pending', created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS invoices (
 id INTEGER PRIMARY KEY AUTOINCREMENT, invoice_no TEXT UNIQUE NOT NULL, customer TEXT NOT NULL,
 amount REAL NOT NULL, status TEXT DEFAULT 'Unpaid', due_date TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS claims (
 id INTEGER PRIMARY KEY AUTOINCREMENT, claim_no TEXT UNIQUE NOT NULL, member TEXT NOT NULL,
 provider TEXT NOT NULL, amount REAL NOT NULL, status TEXT DEFAULT 'Submitted', created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS plans (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, contribution REAL DEFAULT 0,
 benefit_limit REAL DEFAULT 0, active INTEGER DEFAULT 1
);
`);

const seed = db.prepare("SELECT COUNT(*) c FROM users").get().c;
if (!seed) {
  const ins = db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)");
  ins.run("System Administrator","admin@nhis.local",bcrypt.hashSync("Admin@123",10),"Administrator");
  ins.run("Finance Officer","finance@nhis.local",bcrypt.hashSync("Finance@123",10),"Finance");
}
if (db.prepare("SELECT COUNT(*) c FROM members").get().c === 0) {
  const ins=db.prepare("INSERT INTO members(member_no,name,phone,plan,status) VALUES(?,?,?,?,?)");
  ins.run("NHIS-000001","Aisha Musa","08000000001","Standard","Active");
  ins.run("NHIS-000002","Ibrahim Bello","08000000002","Premium","Active");
}
if (db.prepare("SELECT COUNT(*) c FROM providers").get().c === 0) {
  const ins=db.prepare("INSERT INTO providers(provider_no,name,type,status) VALUES(?,?,?,?)");
  ins.run("PROV-0001","City General Hospital","Hospital","Approved");
  ins.run("PROV-0002","Unity Diagnostic Centre","Diagnostic","Pending");
}
if (db.prepare("SELECT COUNT(*) c FROM plans").get().c === 0) {
  const ins=db.prepare("INSERT INTO plans(name,contribution,benefit_limit) VALUES(?,?,?)");
  ins.run("Standard",15000,500000);
  ins.run("Premium",30000,1500000);
}

function auth(req,res,next){
  const h=req.headers.authorization||"";
  try { req.user=jwt.verify(h.replace("Bearer ",""),SECRET); next(); }
  catch { res.status(401).json({error:"Unauthorized"}); }
}
function crud(table, fields){
  return {
    list:(req,res)=>res.json(db.prepare(`SELECT * FROM ${table} ORDER BY id DESC`).all()),
    create:(req,res)=>{
      const vals=fields.map(f=>req.body[f]);
      const qs=fields.map(()=>"?").join(",");
      const info=db.prepare(`INSERT INTO ${table}(${fields.join(",")}) VALUES(${qs})`).run(...vals);
      res.status(201).json(db.prepare(`SELECT * FROM ${table} WHERE id=?`).get(info.lastInsertRowid));
    },
    update:(req,res)=>{
      const sets=fields.map(f=>`${f}=?`).join(",");
      const vals=fields.map(f=>req.body[f]); vals.push(req.params.id);
      db.prepare(`UPDATE ${table} SET ${sets} WHERE id=?`).run(...vals);
      res.json(db.prepare(`SELECT * FROM ${table} WHERE id=?`).get(req.params.id));
    }
  }
}

app.post('/api/auth/login',(req,res)=>{
  const u=db.prepare("SELECT * FROM users WHERE email=? AND active=1").get(req.body.email);
  if(!u || !bcrypt.compareSync(req.body.password,u.password_hash)) return res.status(401).json({error:"Invalid email or password"});
  const token=jwt.sign({id:u.id,name:u.name,email:u.email,role:u.role},SECRET,{expiresIn:"8h"});
  res.json({token,user:{id:u.id,name:u.name,email:u.email,role:u.role}});
});
app.get('/api/me',auth,(req,res)=>res.json(req.user));

const routes = [
  ["members","members",["member_no","name","phone","plan","status"]],
  ["providers","providers",["provider_no","name","type","status"]],
  ["invoices","invoices",["invoice_no","customer","amount","status","due_date"]],
  ["claims","claims",["claim_no","member","provider","amount","status"]],
  ["plans","plans",["name","contribution","benefit_limit","active"]]
];
for(const [url,table,fields] of routes){
  const c=crud(table,fields);
  app.get(`/api/${url}`,auth,c.list);
  app.post(`/api/${url}`,auth,c.create);
  app.put(`/api/${url}/:id`,auth,c.update);
}
app.get('/api/dashboard',auth,(req,res)=>{
  const q=t=>db.prepare(`SELECT COUNT(*) c FROM ${t}`).get().c;
  const revenue=db.prepare("SELECT COALESCE(SUM(amount),0) n FROM invoices WHERE status='Paid'").get().n;
  const outstanding=db.prepare("SELECT COALESCE(SUM(amount),0) n FROM invoices WHERE status!='Paid'").get().n;
  res.json({members:q("members"),providers:q("providers"),claims:q("claims"),invoices:q("invoices"),revenue,outstanding});
});
app.get('/api/users',auth,(req,res)=>res.json(db.prepare("SELECT id,name,email,role,active FROM users ORDER BY id DESC").all()));
app.post('/api/users',auth,(req,res)=>{
  const {name,email,password,role}=req.body;
  const hash=bcrypt.hashSync(password,10);
  const info=db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)").run(name,email,hash,role||"Staff");
  res.status(201).json({id:info.lastInsertRowid,name,email,role:role||"Staff",active:1});
});

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,()=>console.log(`NHIS app running on http://localhost:${PORT}`));
