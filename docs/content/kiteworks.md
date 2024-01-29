---
title: "Kiteworks"
description: "Rclone docs for Kiteworks"
versionIntroduced: "v1.65.2"
---

# {{< icon "fas fa-shield-alt" >}} Kiteworks

Kiteworks is [Secure File Sharing | Kiteworks](https://www.kiteworks.com/).

Paths are specified as `remote:path`

Paths may be as deep as required, e.g., `remote:directory/subdirectory`.

The initial setup for Kiteworks involves getting an oauth2 token from
Kiteworks which you need to do in your browser.  `rclone config` walks
you through it.

## Configuration

Here is an example of how to make a remote called `remote`.  First run:

     rclone config

This will guide you through an interactive setup process:

```
No remotes found, make a new one?
n) New remote
s) Set configuration password
q) Quit config
n/s/q> n
name> remote
Type of storage to configure.
Choose a number from below, or type in your own value
[snip]
XX / Kiteworks
   \ "kiteworks"
[snip]
Storage> kiteworks
Kiteworks App Client Id.
client_id>
Kiteworks App Client Secret.
client_secret>
Host name of Kiteworks account.
hostname> example.kiteworks.com
Access scopes for application. Press Enter for the default (files/* folders/* uploads/* search/* users/Read)
access_scopes>
Use web browser to automatically authenticate rclone with remote?
 * Say Y if the machine running rclone has a web browser you can use
 * Say N if running rclone on a (remote) machine without web browser access
If not sure try Y. If Y failed, try N.
y) Yes
n) No
y/n> y
If your browser doesn't open automatically go to the following link: http://127.0.0.1:53682/auth
Log in and authorize rclone for access
Waiting for code...
Got code

--------------------
[remote]
client_id = 8312a84e-556d-7gc8-7e9d-e19367916d10
client_secret = abcR#ds!6cbxk
hostname = example.kiteworks.com
access_scopes = files/* folders/* uploads/* search/* users/Read
token = {"access_token":"XXX","token_type":"Bearer","refresh_token":"XXX","expiry":"XXX"}
--------------------
y) Yes this is OK
e) Edit this remote
d) Delete this remote
y/e/d> y
```

Once configured you can then use `rclone` like this,

List directories in top level of your Kiteworks

    rclone lsd remote:

List all the files in your Kiteworks

    rclone ls remote:

To copy a local directory to a Kiteworks directory called backup

    rclone copy /home/source remote:backup

### Invalid refresh token

> Expiration for token and refresh token can be set per application.
If you

  * Don't use the kiteworks remote for the specified expiration time of the token.
  * Copy the config file with a kiteworks refresh token in and use it in two places
  * Get an error on a token refresh

then rclone will return an error which includes the text `Invalid
refresh token`.

To fix this you will need to use oauth2 again to update the refresh
token.  You can use the methods in [the remote setup
docs](/remote_setup/), bearing in mind that if you use the copy the
config file method, you should not use that remote on the computer you
did the authentication on.

Here is how to do it.

```
$ rclone config
Current remotes:

Name                 Type
====                 ====
remote               kiteworks

e) Edit existing remote
n) New remote
d) Delete remote
r) Rename remote
c) Copy remote
s) Set configuration password
q) Quit config
e/n/d/r/c/s/q> e
Choose a number from below, or type in an existing value
 1 > remote
remote> remote
--------------------
[remote]
type = kiteworks
client_id = 8312a84e-556d-7gc8-7e9d-e19367916d10
client_secret = abcR#ds!6cbxk
hostname = example.kiteworks.com
access_scopes = files/* folders/* uploads/* search/* users/Read
token = {"access_token":"XXX","token_type":"Bearer","refresh_token":"XXX","expiry":"XXX"}
--------------------
Edit remote
Value "client_id" = "8312a84e-556d-7gc8-7e9d-e19367916d10"
Edit? (y/n)>
y) Yes
n) No
y/n> n
Value "client_secret" = "abcR#ds!6cbxk"
Edit? (y/n)>
y) Yes
n) No
y/n> n
Value "hostname" = "example.kiteworks.com"
Edit? (y/n)>
y) Yes
n) No
y/n> n
Value "access_scopes" = "files/* folders/* uploads/* search/* users/Read"
Edit? (y/n)>
y) Yes
n) No
y/n> n
Remote config
Already have a token - refresh?
y) Yes
n) No
y/n> y
Use web browser to automatically authenticate rclone with remote?
 * Say Y if the machine running rclone has a web browser you can use
 * Say N if running rclone on a (remote) machine without web browser access
If not sure try Y. If Y failed, try N.
y) Yes
n) No
y/n> y
If your browser doesn't open automatically go to the following link: http://127.0.0.1:53682/auth
Log in and authorize rclone for access
Waiting for code...
Got code
--------------------
[remote]
type = kiteworks
client_id = 8312a84e-556d-7gc8-7e9d-e19367916d10
client_secret = abcR#ds!6cbxk
hostname = example.kiteworks.com
access_scopes = files/* folders/* uploads/* search/* users/Read
token = {"access_token":"XXX","token_type":"Bearer","refresh_token":"XXX","expiry":"XXX"}
--------------------
y) Yes this is OK
e) Edit this remote
d) Delete this remote
y/e/d> y
```

### Modification times and hashes

Kiteworks allows modification times to be set on objects accurate to 1 second.
These will be used to detect whether objects need syncing or not.

Kiteworks supports SHA3-256 type hashes, so you can use the `--checksum`
flag.

### Restricted filename characters

File names in Kiteworks are case insensitive and have limitations like the maximum length of a filename is 255, and the minimum length is 1. A file name cannot contain `/` , `\`, `:`, `*`, `"`, `<`, `>`, `|` or non-printable ascii.

### Transfers

Kiteworks supports upload by chunks, and chunk size is set during upload initiate and number of chunks is calculated based on total size and chunk size. Default chunk size is 65_000_000 bytes by default, and it can be changed in the advanced configuration. The chunk size doesn't have a maximum size limit.

### Deleting files

Files you delete with rclone will be marked as deleted, and you still will be able to see them in Deleted content of the folder from which they were removed.
Kiteworks also provides an API to permanently delete files.

{{< rem autogenerated options start" - DO NOT EDIT - instead edit fs.RegInfo in backend/kiteworks/kiteworks.go then run make backenddocs" >}}
### Standard options

Here are the Standard options specific to kiteworks (Kiteworks).

#### --kiteworks-client-id

OAuth Client Id

Properties:

- Config:      client_id
- Env Var:     RCLONE_KITEWORKS_CLIENT_ID
- Type:        string
- Required:    true

#### --kiteworks-client-secret

OAuth Client Secret

Properties:

- Config:      client_secret
- Env Var:     RCLONE_KITEWORKS_CLIENT_SECRET
- Type:        string
- Required:    true

#### --kiteworks-hostname

Host name of Kiteworks account

Properties:

- Config:      hostname
- Env Var:     RCLONE_KITEWORKS_HOSTNAME
- Type:        string
- Required:    true

#### --kiteworks-access-scopes

Access scopes for application

Properties:

- Config:      access_scopes
- Env Var:     RCLONE_KITEWORKS_ACCESS_SCOPES
- Type:        string
- Default:     "files/* folders/* uploads/* search/* users/Read"

### Advanced options

Here are the Advanced options specific to kiteworks (Kiteworks).

#### --kiteworks-hard-delete

Delete files permanently

Properties:

- Config:      hard_delete
- Env Var:     RCLONE_KITEWORKS_HARD_DELETE
- Type:        bool
- Default:     false

#### --kiteworks-chunk-size

Size for upload chunk

Properties:

- Config:      chunk_size
- Env Var:     RCLONE_KITEWORKS_CHUNK_SIZE
- Type:        SizeSuffix
- Default:     60.536Gi

#### --kiteworks-encoding

The encoding for the backend.

See the [encoding section in the overview](/overview/#encoding) for more info.

Properties:

- Config:      encoding
- Env Var:     RCLONE_KITEWORKS_ENCODING
- Type:        Encoding
- Default:     Slash,LtGt,DoubleQuote,Colon,Question,Asterisk,Pipe,BackSlash,Del,Ctl,LeftPeriod,RightPeriod,InvalidUtf8,Dot

#### --kiteworks-description

Description of the remote

Properties:

- Config:      description
- Env Var:     RCLONE_KITEWORKS_DESCRIPTION
- Type:        string
- Required:    false

{{< rem autogenerated options stop >}}

## Server-side operations

Kiteworks supports server-side operations (copy and move) but for now they are not implemented.