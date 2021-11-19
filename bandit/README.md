# Bandit

## Level 0
Logging in via ssh 

## Level 0 -> 1
Use cat 

## Level 1 -> 2
Use cat with "./" prefix to select the "-" file

## Level 2 -> 3
Use cat with either "" or escape whitespace in filename using \

## Level 3 -> 4
Use cat on "hidden" dotfile

## Level 4 -> 5
Check for human readable file in the "inhere" folder: 
```bash
file ./* | grep text
```

## Level 5 -> 6
Level task gave following attributes to search for:
- human-readable
- 1033 bytes in size
- not executable

Reading the `find` man-page gives following options to be useful here:

  - `-readable`
    - Matches files which are readable.

  - `-size n[cwbkMG]`
    - This filters for size on disk. Use c-suffix for bytes.

  - `-perm`
    - This filters for the given file permission bits. Use "-a-x" to filter for
    any files having execute bit for nobody set.

So the searched file can be found using:
```bash
find . -readable -size 1033c -perm -a-x
```

## Level 6 -> 7
Level task gave following attributes to search for:
 - owned by user bandit7
 - owned by group bandit6
 - 33 bytes in size

Reading the `find` man-page gives following options to be useful here:
  - `-user uname`
    - Filter by user owned
  - `-group gname`
    - Filter by groupt owned
  - `-size n[cwbkMG]`
    - Filter by size on disk. Use c-suffix for bytes.

To filter all permission errors redirect stderr to /dev/null using `2>`.

So the searched file can be found using:
```bash
find / -user bandit7 -group bandit6 -size 33c 2> /dev/null 
```

## Level 7 -> 8
Password should be next to the word "millionth" in the `data.txt` file.

Use grep to get the desired line:
```bash
cat data.txt | grep millionth
```

## Level 8 -> 9
Password is only unique line in `data.txt` file.

Reading the `uniq` man-page gives following useful option:
  - `-u, --unique`
    - only print unique lines

But it also states:
*'uniq' does not detect repeated lines unless they are adjacent.
You may want to sort the input first, or use 'sort -u' without 'uniq'.*

So we have to use `sort` before piping to `uniq`:
```bash
cat data.txt | sort | uniq -u
```

## Level 9 -> 10
Password is one of the few human-readable lines and is preceded by several
"-" characters.

So we can just use a combination of `cat`, `strings` and `grep`:
```bash
cat data.txt | strings | grep "=="
```

## Level 10 -> 11
Password is stored in `data.txt` which is base64 encoded.

Use `base64` to decode:
```bash
cat data.txt | base64 -d
```

## Level 11 -> 12
The password is stored in `data.txt` and "have been rotated by 13 positions".
This is basic ROT13 "encryption".

Goal is to shift every character in `data.txt` by 13 positions.
Reading the `tr` man-page shows we can just specify which character should
be replaced by which character: `tr [OPTION]... SET1 [SET2]`

So we translate a-m to n-z and vice-versa. Of course we also need to translate
upper-case A-M and N-Z. So we get:
```bash
cat data.txt | tr a-mn-zA-MN-Z n-za-mN-ZA-M
```

This maps `a-m -> n-z` and `n-z -> a-m` and equally with upper-case.

This can also be shortened by writing:
```bash
cat data.txt | tr a-zA-Z n-za-mN-ZA-M
```

This is possible because `a-zA-Z` and `n-za-mN-ZA-M` are obviously equally long
ranges and when split automatically `a-z` is correctly split in half between
`m` and `n`.

## Level 12 -> 13
The password is stored in the `data.txt` file which is a hexdump of a
multiple times compressed file. It can be fully decompressed and read 
by determining the compression utility used with the `file` command and then 
decompressing/extracting it either with `tar`, `gzip` or `bzip2`.

To convert the hexdump to a file `xxd -r` can be used.

## Level 13 -> 14
The next level can be solved by using the given private ssh-key and login
with the `bandit14` account by:
```bash
ssh bandit14@localhost -i sshkey.private
```

## Level 14 -> 15
The current password is found at `/etc/bandit_pass/bandit14`.
It can be used to send it via tcp (by using `netcat`) to the port 30000 of
the current machine (`localhost`) the service behind that port will answer
with the next password:

```bash
netcat localhost 30000
```

## Level 15 -> 16
The next password is retrieved by sending the current password to the port
30001 using ssl/tls:

```bash
openssl s_client -connect localhost:30001
```

## Level 16 -> 17
Use nmap to scan for all tcp services running on localhost:
```bash
nmap -sT localhost -p 31000-32000
```

Option `-sT` is used for performing a "TCP connect scan". It tries to fully
perform the TCP handshake on every given port. It is normally used when
SYN (`-sS`) scan is not an option (e.g. no privileged user available). It's
important to note that `-sT` creates a lot of noise on the target system because
every TCP connection try will be logged on it.

The scan results in 5 different services. The `openssl s_client` tool can be
used to check for a valid ssl service behind each of these ports. Port `31790`
responds with an RSA-KEY which can be used to login into the next level using
`ssh -l <key> <host>`

## Level 17 -> 18
This level can be solved by comparing `passwords.new` to `passwords.old`
with the `diff` tool:

```bash
diff passwords.new --to-file passwords.old
```

which is equivalent to

```bash
diff passwords.new passwords.old
```

but yields a better readability with respect to the output:

```
42c42 
< newtext
--- 
> oldtext
```

The output means:
  - line `42` was changed (`c`) in `passwords.new` and it
  corresponds to the line `42` in `passwords.old`
  - `< ...` following content is the new content after the change
  - `> ...` following content is the old content before the change

The password for the next level is the new version of the changed line.

## Level 18 -> 19
The bashrc of the `bandit18` user exits the shell.

To prevent loading of the bashrc we can use `/bin/sh` instead:

```bash
ssh -p 2220 bandit18@bandit.labs.overthewire.org /bin/sh
```

## Level 19 -> 20
For this level you only need to execute the bandit20-do binary which
has the [setuid-bit](https://en.wikipedia.org/wiki/Setuid#When_set_on_an_executable_file) set and invokek cat to print the password:

```bash
./bandit20-do cat /etc/bandit_pass/bandit20
```

## Level 20 -> 21
In this level another `setuid`-binary is given which connects to a given port
and responds which the next password when receiving the last password on that
port via TCP.

To list on a given port we can use `netcat`:
```bash
nc -vlp 4242
```

Where
  - `-v`
    - gives verbose output
  - `-l`
    - sets the listen mode which waits for an incoming connection
  - `-p`
    - specifies the port to listen on

Now in another session (i.e. another `tmux` pane/window) the setuid binary
can be invoked with the port `netcat` is listening on:

```
./suconnect 4242
```

A TCP-connection is established and the last password can be entered from the
`netcat` session which results in the `suconnect` binary responding with the
next password.

gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr
## Level 21 -> 22
The level task says there is a cronjob configured which can be found under
`/etc/cron.d/`:

```bash
#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```

As the file that is being written to can be read as any user we can just use
`cat` to get the next password that it contains.

## Level 22 -> 23
Again we are given a shell script that is periodically executed as a cronjob:

```bash
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget
```

So the `$mytarget` variable yields the name of the file which contains the next
password. We can just execute the expression
`echo I am user $myname | md5sum | cut -d ' ' -f 1` by replacing `$myname` with
`bandit23` and entering it into a shell (e.g. `bash`).

jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n

## Level 23 -> 24
The given script that is executed by cron as `bandit24` looks like:

```bash
#!/bin/bash

myname=$(whoami)

cd /var/spool/$myname
echo "Executing and deleting all scripts in /var/spool/$myname:"
for i in * .*;
do
    if [ "$i" != "." -a "$i" != ".." ];
    then
        echo "Handling $i"
        owner="$(stat --format "%U" ./$i)"
        if [ "${owner}" = "bandit23" ]; then
            timeout -s 9 60 ./$i
        fi
        rm -f ./$i
    fi
done
```

It therefore executes every script in `/var/spool/bandit24` that is owned
by user `bandit23` as user `bandit24` and deletes it afterwards.

So you can create a file `bandit24` can write to and we (as user `bandit23`)
can read. So we create a directory `/tmp/b24passwd` and a file `pass` inside it.
We use `chmod o+w pass` to give write permissions to everybody.

We then create a script `getpass.sh` in `/var/spool/bandit24/getpass.sh`:
```bash
#!/bin/bash

cat /etc/bandit_pass/bandit24 >> /tmp/b24passwd/pass
```

We also need to grant execute permissions: `chmod +x /var/spool/bandit24/getpass.sh`
The password will then be printed into `/tmp/b24passwd/pass`.


UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ

## Level 24 -> 25
The task states the password can be retrieved by sending the last password
and a secret 4-digit pin to port 30002 on localhost via tcp and the pin
can only be retrieved by bruteforcing. I therefore wrote this crappy little
python script to retrieve it:

```bash
#!/usr/bin/env python3
# Test
import socket
import select
import sys

def main():
    if len(sys.argv) > 1:
        start = int(sys.argv[1])
    else:
        start = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 30002))
    sock.setblocking(0)
    read_from_socket(sock)

    for i in range(start, 10000):
        pin = str(i).zfill(4)
        print('Trying %s' %(pin))
        while True:
            try:
                sock.send(('UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ %s\n' %(pin)).encode('utf-8'))
                break
            except BrokenPipeError:
                sock = reconnect_socket()
        while True:
            answer = read_from_socket(sock)
            if answer: break
        if not "Wrong" in answer:
            print("Password found! Pin: %s" %(pin))
            print("Password: %s" %(answer))
            break


def read_from_socket(opensock):
    answer = ""
    while True:
        ready = select.select([opensock], [], [], 0.001)
        if not ready[0]: continue;
        response = opensock.recv(1024)
        #if not response: break
        answer += response.decode('utf-8')
        return answer

def reconnect_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 30002))
    sock.setblocking(0)
    read_from_socket(sock)
    return sock

if __name__ == "__main__":
    main()
```

TIL: First time working with sockets in python!
I didnt want to care about concurrency, so i decided it would be easier to
allow a starting index to be given as argument and just running the script multiple
times via tmux.

The pane starting at index 2500 caught it fast:

```
Password found! Pin: 2588
Password: Correct!
The password of user bandit25 is uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG
```

## Level 25 -> 26
A ssh key for the `bandit26` user is provided to us. When we try to login
via ssh we get:

```
  _                     _ _ _   ___   __  
 | |                   | (_) | |__ \ / /  
 | |__   __ _ _ __   __| |_| |_   ) / /_  
 | '_ \ / _` | '_ \ / _` | | __| / / '_ \ 
 | |_) | (_| | | | | (_| | | |_ / /| (_) |
 |_.__/ \__,_|_| |_|\__,_|_|\__|____\___/ 
Connection to localhost closed.
```

A look into `/etc/passwd` reveals the shell in use:

```
bandit26:x:11026:11026:bandit level 26:/home/bandit26:/usr/bin/showtext
```

The `showtext` file looks like this:

```bash
#!/bin/sh

export TERM=linux

more ~/text.txt
exit 0
```

We cannot bypass this shell by specifying commands to the ssh command since
they also will be executed by this "shell" and therefore will only print the
content of `text.txt`. So the only thing we can maybe influence is what happens
while `more` is invoked. The solution here is to resize the terminal window
so `more` will not terminate immediately. Pressing `?` will let us see all
availabe commands. There are two commands that actually execute stuff:

- !\<cmd> or :!\<cmd>
  - Execute <cmd> in a subshell
and
- v
  - Start up /usr/bin/vi at current line

The first one again just invoke the default shell which again just prints
the content of `text.txt`.

The second one invokes `vì` and `vi` has a command mode. But executing commands
in `vi` again just invokes the default shell. Lookin up how the shell commands
from `vi` can be invoked I stumbled upon:

*The type of shell that is started is
determined by the $SHELL variable. You can specify that some other shell is to
be started by setting the vi shell option*

So we can set the shell to be used: `:set shell=/bin/bash`

5czgV9L3Xx8JPOyRbXh6lQbmIOWvPT6Z

## Level 26 -> 27

Now we can execute shell commands in vi and get the next password via the given
`setuid`-binary:
```
:!~/bandit27-do cat /etc/bandit_pass/bandit27
```

3ba3118a22e93127a4ed485be72ef5ea

## Level 27 -> 28
This level can quickly be solved by cloning the provided git repository and
reading the `README.md` it contains.

0ef186ac70e04ea33b4c1853d2526fa2

## Level 28 -> 29
We again are provided a git repository to clone. It also contains a `READE.md`
but the password seems to be removed: 
```
# Bandit Notes
Some notes for level29 of bandit. 

## credentials

- username: bandit29
- password: xxxxxxxxxx                                                                              
```

The `git log` reveals there are three commits. The most recent one has the message
`fix info leak`. We can undo the most recent commit via `git reset HEAD~1 --hard`.

Now we can read the password inside `README.md`:
```
# Bandit Notes
Some notes for level29 of bandit.

## credentials

- username: bandit29
- password: bbc96594b4e001778eee9975372716b2
```

## Level 29 -> 30
The git repository for this level also has a `README.md` file with the following
content:

```
# Bandit Notes                                                                                   
Some notes for bandit30 of bandit.              
                                                
## credentials                                                                                   
                                                
- username: bandit30                            
- password: <no passwords in production!>       
```                                              

This time there is no sign of the password in the commit history. There is
a `dev` branch though. Using `checkout dev` we can switch to the `dev` branch.
In this branch the `README.md` was modified and contains the next password:

```
# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: 5b90576bedb2cc04c86a9e924ce42faf
```

## Level 30 -> 31
This repository shows only one commit which created the file `README.md`:

```
commit 3aefa229469b7ba1cc08203e5d8fa299354c496b
Author: Ben Dover <noone@overthewire.org>
Date:   Thu May 7 20:14:54 2020 +0200

    initial commit of README.md

diff --git a/README.md b/README.md
new file mode 100644
index 0000000..029ba42
--- /dev/null
+++ b/README.md
@@ -0,0 +1 @@
+just an epmty file... muahaha
```

There is also only the `master` branch and no other branch available.
Poking around in the `.git` directory shows there is a tag named `secret` referenced
in `packed-refs`:
```
# pack-refs with: peeled fully-peeled 
3aefa229469b7ba1cc08203e5d8fa299354c496b refs/remotes/origin/master
f17132340e8ee6c159e0a4a6bc6f80e1da3b1aea refs/tags/secret
```

By using `git show` to print details about the tag we get the next password:
```
47e603bb428404d265f59c42920d81e5
``` 

## Level 31 -> 32
The `README.md` in the given repository states:
```
This time your task is to push a file to the remote repository.

Details:
    File name: key.txt
    Content: 'May I come in?'
    Branch: master
```

So we create the `key.txt` file:
```bash
echo "May I come in?" > key.txt
```

We also need to delete the line in the `.gitignore` that would ignore all
`.txt` files.

We then stage, commit and push the changes and are prompted with the new password:
```
Counting objects: 4, done.
Delta compression using up to 2 threads.
Compressing objects: 100% (2/2), done.
Writing objects: 100% (4/4), 336 bytes | 0 bytes/s, done.
Total 4 (delta 0), reused 0 (delta 0)
remote: ### Attempting to validate files... ####
remote: 
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote: 
remote: Well done! Here is the password for the next level:
remote: 56a9bf19c63d650ce78e6ec0354ee45e
remote: 
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote: 
To ssh://localhost/home/bandit31-git/repo
 ! [remote rejected] master -> master (pre-receive hook declined)
error: failed to push some refs to 'ssh://bandit31-git@localhost/home/bandit31-git/repo'
```

## Level 32 -> 33
In this level we are trapped in a "uppercase shell" which transforms any alphabetic
character to uppercase. Therefore we cannot use common commands because the
shell cannot find them after being transformed:

```
>> pwd
sh: 1: PWD: not found
>> id
sh: 1: ID: not found
>> 
```

But we can see that `sh` is used here. `sh` is the POSIX compliant alternative
to `bash` which specific implementation is used depends on the distribution
you are on. The overthewire machines are using Devuan (Debian based).
`sh` points to `dash` in both Debian and Devuan. We can read up about `dash` here:

https://linux.die.net/man/1/dash

In the section `Special Parameters` we can read about some special parameters
that can be used inside this shell. One of them is `$0`:

```
0 (Zero.)' Expands to the name of the shell or shell script.
```

NOTE: This special parameter is also available in bash 
(see section "Special Parameters" on https://man7.org/linux/man-pages/man1/bash.1.html)
but it's important to note that `sh` is NOT `bash` (although on some distributions
`sh` is a link to `bash` with a special flag).

So when we enter `$0` into the "uppercase shell" we enter into `sh` and can then
enter `/bin/bash` to get to our beloved `bash` shell if we want to.
We can now just cat the password from the common space (because the shell
belongs to `bandit33` and has the `setuid` flag set:
```
c9c3199ddf4121b10cf581a98d51caee
```

# THE END!
