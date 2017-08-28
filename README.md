# wai-secure-cookies

I extracted a WAI middleware to automatically encrypt and sign cookies.

---

** WARNING **

I am not a cryptographer, and the crypto libraries in Haskell are not nearly as easy to use as what I'm used to in Ruby, so I wouldn't depend on this for a serious project until it's had some proper eyes on it.

---

# Usage

Populate the following environment variables in your WAI application process:

```
WAI\_COOKIE\_VALIDATION\_KEY # key to sign cookie names and values
WAI\_COOKIE\_ENCRYPTION\_KEY # key to encrypt cookie names and values
```

You can generate random keys with `waicookie-genkey`:

```
waicookie-genkey <key type> ...
key types: encryption
           validation
```
