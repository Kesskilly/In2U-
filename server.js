import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Database from 'better-sqlite3';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import { WebSocketServer } from 'ws';

const app = express();
const PORT = Number(process.env.PORT || 10000);
const JWT_SECRET = String(process.env.JWT_SECRET || 'change-this-in2u-secret');

app.use(cors({origin:'*',methods:['GET','POST','PATCH','DELETE','OPTIONS'],allowedHeaders:['Content-Type','Authorization']}));
app.use(express.json({limit:'40mb'}));

const db = new Database(process.env.SQLITE_PATH || 'in2u.db');
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

function ensureSchema(){
  db.exec(`
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      username TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      bio TEXT DEFAULT '', photo_url TEXT DEFAULT '',
      is_private INTEGER DEFAULT 0, allow_messages INTEGER DEFAULT 1,
      approve_followers INTEGER DEFAULT 0, show_followers INTEGER DEFAULT 1,
      show_following INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS posts(
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
      caption TEXT DEFAULT '', media_json TEXT DEFAULT '[]', created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS reactions(
      id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
      emoji TEXT NOT NULL, UNIQUE(post_id,user_id,emoji),
      FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS comments(
      id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
      text TEXT NOT NULL, parent_id INTEGER DEFAULT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(parent_id) REFERENCES comments(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS follows(
      id INTEGER PRIMARY KEY AUTOINCREMENT, follower_id INTEGER NOT NULL, following_id INTEGER NOT NULL,
      status TEXT DEFAULT 'accepted', created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(follower_id,following_id),
      FOREIGN KEY(follower_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(following_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS conversations(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS conversation_members(
      conversation_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
      PRIMARY KEY(conversation_id,user_id),
      FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS messages(
      id INTEGER PRIMARY KEY AUTOINCREMENT, conversation_id INTEGER NOT NULL, sender_id INTEGER NOT NULL,
      text TEXT NOT NULL DEFAULT '', media_url TEXT DEFAULT '', media_type TEXT DEFAULT '', reply_to_id INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
      FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(reply_to_id) REFERENCES messages(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS message_reactions(
      message_id INTEGER NOT NULL, user_id INTEGER NOT NULL, emoji TEXT NOT NULL,
      PRIMARY KEY(message_id,user_id,emoji),
      FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id,id);
    CREATE INDEX IF NOT EXISTS idx_members_user ON conversation_members(user_id,conversation_id);
  `);
}
ensureSchema();
try{db.prepare("SELECT name FROM conversations LIMIT 1").get();}catch{db.exec("ALTER TABLE conversations ADD COLUMN name TEXT DEFAULT ''")}

const cloudName=String(process.env.CLOUDINARY_CLOUD_NAME||'').trim();
const cloudKey=String(process.env.CLOUDINARY_API_KEY||'').trim();
const cloudSecret=String(process.env.CLOUDINARY_API_SECRET||'').trim();
const cloudinaryReady=!!(cloudName&&cloudKey&&cloudSecret);
if(cloudinaryReady) cloudinary.config({cloud_name:cloudName,api_key:cloudKey,api_secret:cloudSecret,secure:true});

const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:100*1024*1024},fileFilter:(req,file,cb)=>/^(image|video|audio)\//i.test(file.mimetype||'')?cb(null,true):cb(new Error('Only image, video and audio files are supported'))});

function signToken(id){return jwt.sign({sub:String(id)},JWT_SECRET,{expiresIn:'30d'})}
function publicUser(u){return {id:u.id,name:u.name,username:u.username,email:u.email,bio:u.bio||'',photoUrl:u.photo_url||'',isPrivate:!!u.is_private,allowMessages:u.allow_messages!==0,approveFollowers:!!u.approve_followers,showFollowers:u.show_followers!==0,showFollowing:u.show_following!==0}}
function auth(req,res,next){const h=String(req.headers.authorization||'');const token=h.startsWith('Bearer ')?h.slice(7).trim():'';if(!token)return res.status(401).json({error:'Authentication required'});try{const d=jwt.verify(token,JWT_SECRET),id=Number(d.sub),u=db.prepare('SELECT * FROM users WHERE id=?').get(id);if(!Number.isInteger(id)||!u)throw new Error();req.userId=id;req.user=u;next()}catch{return res.status(401).json({error:'Invalid or expired token'})}}
function authToken(token){try{const d=jwt.verify(token,JWT_SECRET),id=Number(d.sub);return db.prepare('SELECT * FROM users WHERE id=?').get(id)||null}catch{return null}}

function uploadBuffer(buffer,mimetype){return new Promise((resolve,reject)=>{if(!cloudinaryReady)return reject(new Error('Cloudinary is not configured on the server'));const resourceType=/^(video|audio)\//i.test(mimetype)?'video':'image';const stream=cloudinary.uploader.upload_stream({folder:'in2u',resource_type:resourceType,unique_filename:true,overwrite:false},(err,r)=>err?reject(new Error(err.message||'Cloudinary upload failed')):resolve({url:r.secure_url||r.url,publicId:r.public_id,resourceType:r.resource_type,format:r.format,mimeType:mimetype}));stream.end(buffer)})}

app.get('/api/health',(req,res)=>res.json({ok:true,service:'In2U backend',cloudinary:cloudinaryReady,time:new Date().toISOString(),multiplayer:true}));

app.post('/api/auth/signup',async(req,res)=>{try{const name=String(req.body?.name||'').trim(),email=String(req.body?.email||'').trim().toLowerCase(),password=String(req.body?.password||''),username=String(req.body?.username||'').trim().toLowerCase();if(!name||!email||!password||!username)return res.status(400).json({error:'Name, email, username and password are required'});if(password.length<8)return res.status(400).json({error:'Password must be at least 8 characters'});if(db.prepare('SELECT id FROM users WHERE email=? OR username=?').get(email,username))return res.status(409).json({error:'Email or username already exists'});const hash=await bcrypt.hash(password,12),info=db.prepare('INSERT INTO users(name,username,email,password_hash) VALUES(?,?,?,?)').run(name,username,email,hash),u=db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid);res.json({token:signToken(u.id),user:publicUser(u)})}catch(e){console.error(e);res.status(500).json({error:'Could not create account'})}});
app.post('/api/auth/login',async(req,res)=>{try{const email=String(req.body?.email||'').trim().toLowerCase(),password=String(req.body?.password||''),u=db.prepare('SELECT * FROM users WHERE email=?').get(email);if(!u||!(await bcrypt.compare(password,u.password_hash)))return res.status(401).json({error:'Invalid email or password'});res.json({token:signToken(u.id),user:publicUser(u)})}catch(e){res.status(500).json({error:'Could not log in'})}});
app.post('/api/auth/logout',auth,(req,res)=>res.json({ok:true}));
app.get('/api/me',auth,(req,res)=>res.json({user:publicUser(req.user)}));
app.patch('/api/me',auth,(req,res)=>{try{const b=req.body||{},name=String(b.name??req.user.name).trim()||req.user.name,username=String(b.username??req.user.username).trim().toLowerCase()||req.user.username,bio=String(b.bio??req.user.bio??''),photo=String(b.photoUrl??req.user.photo_url??''),priv=b.isPrivate===undefined?req.user.is_private:!!b.isPrivate,msg=b.allowMessages===undefined?req.user.allow_messages:!!b.allowMessages,approve=b.approveFollowers===undefined?req.user.approve_followers:!!b.approveFollowers,sf=b.showFollowers===undefined?req.user.show_followers:!!b.showFollowers,sg=b.showFollowing===undefined?req.user.show_following:!!b.showFollowing;if(db.prepare('SELECT id FROM users WHERE username=? AND id<>?').get(username,req.userId))return res.status(409).json({error:'Username already exists'});db.prepare('UPDATE users SET name=?,username=?,bio=?,photo_url=?,is_private=?,allow_messages=?,approve_followers=?,show_followers=?,show_following=? WHERE id=?').run(name,username,bio,photo,priv?1:0,msg?1:0,approve?1:0,sf?1:0,sg?1:0,req.userId);res.json({user:publicUser(db.prepare('SELECT * FROM users WHERE id=?').get(req.userId))})}catch(e){res.status(500).json({error:'Could not update profile'})}});

app.post('/api/uploads',auth,(req,res)=>upload.single('file')(req,res,async err=>{if(err)return res.status(400).json({error:err.message});if(!req.file)return res.status(400).json({error:'No file uploaded'});try{res.json(await uploadBuffer(req.file.buffer,req.file.mimetype))}catch(e){res.status(502).json({error:e.message||'Media upload failed'})}}));
app.post('/api/upload',auth,(req,res)=>res.status(410).json({error:'Old upload endpoint. Use /api/uploads.'}));

function decoratePost(p){const reactions=db.prepare('SELECT emoji,COUNT(*) n FROM reactions WHERE post_id=? GROUP BY emoji').all(p.id),ru={};for(const r of db.prepare('SELECT r.emoji,u.name,u.username,u.photo_url FROM reactions r JOIN users u ON u.id=r.user_id WHERE r.post_id=? ORDER BY r.id DESC').all(p.id))(ru[r.emoji]??=[]).push({name:r.name,handle:'@'+r.username,photo:r.photo_url||''});const comments=db.prepare('SELECT c.*,u.name,u.username FROM comments c JOIN users u ON u.id=c.user_id WHERE c.post_id=? ORDER BY c.id ASC').all(p.id);let media=[];try{media=JSON.parse(p.media_json||'[]')}catch{}return {id:p.id,name:p.name,username:p.username,photo:p.photo_url||'',caption:p.caption||'',media,reactions:Object.fromEntries(reactions.map(x=>[x.emoji,x.n])),reactionUsers:ru,comments:comments.map(c=>({id:c.id,user:c.name,text:c.text,parentId:c.parent_id,replies:[]})),created_at:p.created_at}};
app.post('/api/posts',auth,(req,res)=>{try{const caption=String(req.body?.caption||''),media=Array.isArray(req.body?.media)?req.body.media.filter(x=>typeof x==='string'&&/^https?:\/\//i.test(x)).slice(0,10):[],info=db.prepare('INSERT INTO posts(user_id,caption,media_json) VALUES(?,?,?)').run(req.userId,caption,JSON.stringify(media));res.json({ok:true,id:Number(info.lastInsertRowid)})}catch(e){res.status(500).json({error:'Could not create post'})}});
app.get('/api/feed',auth,(req,res)=>{const rows=db.prepare('SELECT p.*,u.name,u.username,u.photo_url FROM posts p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 100').all();res.json({posts:rows.map(decoratePost)})});
app.post('/api/posts/:id/reactions',auth,(req,res)=>{try{const pid=Number(req.params.id),emoji=String(req.body?.emoji||'❤️');if(!db.prepare('SELECT id FROM posts WHERE id=?').get(pid))return res.status(404).json({error:'Post not found'});db.prepare('INSERT OR IGNORE INTO reactions(post_id,user_id,emoji) VALUES(?,?,?)').run(pid,req.userId,emoji);res.json({ok:true})}catch(e){res.status(500).json({error:'Could not add reaction'})}});
app.post('/api/posts/:id/comments',auth,(req,res)=>{try{const pid=Number(req.params.id),text=String(req.body?.text||'').trim(),parent=req.body?.parentId==null?null:Number(req.body.parentId);if(!text)return res.status(400).json({error:'Comment cannot be empty'});if(!db.prepare('SELECT id FROM posts WHERE id=?').get(pid))return res.status(404).json({error:'Post not found'});if(parent!==null&&!db.prepare('SELECT id FROM comments WHERE id=? AND post_id=?').get(parent,pid))return res.status(400).json({error:'Reply target not found'});db.prepare('INSERT INTO comments(post_id,user_id,text,parent_id) VALUES(?,?,?,?)').run(pid,req.userId,text,parent);res.json({ok:true})}catch(e){res.status(500).json({error:'Could not add comment'})}});

app.get('/api/users/search',auth,(req,res)=>{const q=String(req.query.q||'').trim().toLowerCase();const rows=q?db.prepare('SELECT * FROM users WHERE username LIKE ? OR name LIKE ? ORDER BY name LIMIT 30').all('%'+q+'%','%'+q+'%'):db.prepare('SELECT * FROM users ORDER BY id DESC LIMIT 30').all();res.json({users:rows.map(publicUser)})});
app.get('/api/users/:username',auth,(req,res)=>{const username=String(req.params.username).replace(/^@/,'').toLowerCase(),u=db.prepare('SELECT * FROM users WHERE username=?').get(username);if(!u)return res.status(404).json({error:'User not found'});res.json({user:publicUser(u)})});
app.get('/api/users/:id/followers',auth,(req,res)=>{const rows=db.prepare("SELECT u.* FROM follows f JOIN users u ON u.id=f.follower_id WHERE f.following_id=? AND f.status='accepted'").all(Number(req.params.id));res.json({users:rows.map(publicUser)})});
app.get('/api/users/:id/following',auth,(req,res)=>{const rows=db.prepare("SELECT u.* FROM follows f JOIN users u ON u.id=f.following_id WHERE f.follower_id=? AND f.status='accepted'").all(Number(req.params.id));res.json({users:rows.map(publicUser)})});
app.post('/api/users/:id/follow',auth,(req,res)=>{try{const id=Number(req.params.id);if(id===req.userId)return res.status(400).json({error:'You cannot follow yourself'});const target=db.prepare('SELECT * FROM users WHERE id=?').get(id);if(!target)return res.status(404).json({error:'User not found'});const status=target.approve_followers?'pending':'accepted';db.prepare('INSERT INTO follows(follower_id,following_id,status) VALUES(?,?,?) ON CONFLICT(follower_id,following_id) DO UPDATE SET status=excluded.status').run(req.userId,id,status);res.json({status})}catch(e){res.status(500).json({error:'Could not follow user'})}});

function memberOf(cid,uid){return !!db.prepare('SELECT 1 FROM conversation_members WHERE conversation_id=? AND user_id=?').get(cid,uid)}
function conversationSummary(cid,uid){const conv=db.prepare('SELECT * FROM conversations WHERE id=?').get(cid);const members=db.prepare('SELECT u.* FROM conversation_members cm JOIN users u ON u.id=cm.user_id WHERE cm.conversation_id=? AND cm.user_id<>?').all(cid,uid);const last=db.prepare('SELECT text,media_url,media_type,created_at FROM messages WHERE conversation_id=? ORDER BY id DESC LIMIT 1').get(cid);return {id:cid,type:members.length>1?'group':'direct',name:conv?.name||'',members:members.map(publicUser),user:members.length===1?publicUser(members[0]):null,last:last||null}}
function messageShape(r,uid){return {id:r.id,conversationId:r.conversation_id,senderId:r.sender_id,sender:r.sender_name||'',username:r.sender_username||'',from:r.sender_id===uid?'me':'them',text:r.text||'',media:r.media_url||'',mediaType:r.media_type||'',replyToId:r.reply_to_id||null,reply:r.reply_text||'',time:new Date(r.created_at).toLocaleTimeString([],{hour:'numeric',minute:'2-digit'}),createdAt:r.created_at,reactions:[]}}
function messageRow(id){return db.prepare('SELECT m.*,u.name sender_name,u.username sender_username,r.text reply_text FROM messages m JOIN users u ON u.id=m.sender_id LEFT JOIN messages r ON r.id=m.reply_to_id WHERE m.id=?').get(id)}

app.get('/api/conversations',auth,(req,res)=>{const rows=db.prepare('SELECT c.id FROM conversations c JOIN conversation_members cm ON cm.conversation_id=c.id WHERE cm.user_id=? ORDER BY c.id DESC').all(req.userId);res.json({conversations:rows.map(x=>conversationSummary(x.id,req.userId))})});
app.post('/api/conversations',auth,(req,res)=>{try{let ids=Array.from(new Set((Array.isArray(req.body?.memberIds)?req.body.memberIds:[]).map(Number).filter(Number.isInteger)));if(!ids.includes(req.userId))ids.push(req.userId);if(ids.length<2)return res.status(400).json({error:'Choose at least one other user'});const qs=ids.map(()=>'?').join(',');const users=db.prepare('SELECT id FROM users WHERE id IN ('+qs+')').all(...ids);if(users.length!==ids.length)return res.status(404).json({error:'One or more users not found'});if(ids.length===2){const other=ids.find(x=>x!==req.userId);const ex=db.prepare('SELECT c.id FROM conversations c JOIN conversation_members a ON a.conversation_id=c.id AND a.user_id=? JOIN conversation_members b ON b.conversation_id=c.id AND b.user_id=? WHERE (SELECT COUNT(*) FROM conversation_members x WHERE x.conversation_id=c.id)=2 LIMIT 1').get(req.userId,other);if(ex)return res.json({conversation:conversationSummary(ex.id,req.userId)})}const tx=db.transaction(()=>{const info=db.prepare('INSERT INTO conversations(name) VALUES(?)').run(groupName);const cid=Number(info.lastInsertRowid);const s=db.prepare('INSERT INTO conversation_members(conversation_id,user_id) VALUES(?,?)');ids.forEach(uid=>s.run(cid,uid));return cid});const cid=tx();res.status(201).json({conversation:conversationSummary(cid,req.userId)})}catch(e){console.error(e);res.status(500).json({error:'Could not create conversation'})}});
app.get('/api/conversations/:id/messages',auth,(req,res)=>{const cid=Number(req.params.id);if(!memberOf(cid,req.userId))return res.status(403).json({error:'You are not a member of this conversation'});const limit=Math.min(Math.max(Number(req.query.limit)||100,1),200);const rows=db.prepare('SELECT m.*,u.name sender_name,u.username sender_username,r.text reply_text FROM messages m JOIN users u ON u.id=m.sender_id LEFT JOIN messages r ON r.id=m.reply_to_id WHERE m.conversation_id=? ORDER BY m.id DESC LIMIT ?').all(cid,limit).reverse();res.json({messages:rows.map(r=>messageShape(r,req.userId))})});
app.post('/api/conversations/:id/messages',auth,(req,res)=>{try{const cid=Number(req.params.id);if(!memberOf(cid,req.userId))return res.status(403).json({error:'You are not a member of this conversation'});const text=String(req.body?.text||'').trim(),media=String(req.body?.media||'').trim(),mediaType=String(req.body?.mediaType||'').trim(),reply=req.body?.replyToId==null?null:Number(req.body.replyToId);if(!text&&!media)return res.status(400).json({error:'Message cannot be empty'});if(reply!==null&&!db.prepare('SELECT id FROM messages WHERE id=? AND conversation_id=?').get(reply,cid))return res.status(400).json({error:'Reply target not found'});const info=db.prepare('INSERT INTO messages(conversation_id,sender_id,text,media_url,media_type,reply_to_id) VALUES(?,?,?,?,?,?)').run(cid,req.userId,text,media,mediaType,reply);const msg=messageShape(messageRow(info.lastInsertRowid),req.userId);broadcast(cid,{type:'message:new',message:msg});res.status(201).json({message:msg})}catch(e){console.error(e);res.status(500).json({error:'Could not send message'})}});
app.post('/api/conversations/:id/reactions',auth,(req,res)=>{const cid=Number(req.params.id),mid=Number(req.body?.messageId),emoji=String(req.body?.emoji||'❤️');if(!memberOf(cid,req.userId))return res.status(403).json({error:'You are not a member of this conversation'});if(!db.prepare('SELECT id FROM messages WHERE id=? AND conversation_id=?').get(mid,cid))return res.status(404).json({error:'Message not found'});db.prepare('INSERT OR IGNORE INTO message_reactions(message_id,user_id,emoji) VALUES(?,?,?)').run(mid,req.userId,emoji);broadcast(cid,{type:'message:reaction',messageId:mid,emoji,userId:req.userId});res.json({ok:true})});

app.use((err,req,res,next)=>{console.error('Unhandled server error:',err);res.status(500).json({error:'Server error'})});

const server=app.listen(PORT,'0.0.0.0',()=>console.log('In2U backend running on port '+PORT));
const wss=new WebSocketServer({server,path:'/ws'});
const sockets=new Map();
function broadcast(cid,payload){for(const [ws,info] of sockets){if(info.conversations.has(cid)&&ws.readyState===1)ws.send(JSON.stringify(payload))}}
wss.on('connection',(ws,req)=>{const url=new URL(req.url,'http://localhost');const user=authToken(url.searchParams.get('token')||'');if(!user){ws.close(1008,'Unauthorized');return}const info={userId:user.id,conversations:new Set()};sockets.set(ws,info);ws.send(JSON.stringify({type:'connected',userId:user.id}));ws.on('message',raw=>{try{const m=JSON.parse(String(raw));if(m.type==='subscribe'){const cid=Number(m.conversationId);if(memberOf(cid,user.id))info.conversations.add(cid)}}catch{}});ws.on('close',()=>sockets.delete(ws))});
