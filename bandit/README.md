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

# Level 5 -> 6
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

# Level 6 -> 7
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

# Level 7 -> 8
Password should be next to the word "millionth" in the `data.txt` file.

Use grep to get the desired line:
```bash
cat data.txt | grep millionth
```

# Level 8 -> 9
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

# Level 9 -> 10
Password is one of the few human-readable lines and is preceded by several
"-" characters.

So we can just use a combination of `cat`, `strings` and `grep`:
```bash
cat data.txt | strings | grep "=="
```

# Level 10 -> 11
Password is stored in `data.txt` which is base64 encoded.

Use `base64` to decode:
```bash
cat data.txt | base64 -d
```

# Level 11 -> 12
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

# Level 12 -> 13
The password is stored in the `data.txt` file which is a hexdump of a
multiple times compressed file. It can be fully decompressed and read 
by determining the compression utility used with the `file` command and then 
decompressing/extracting it either with `tar`, `gzip` or `bzip2`.

To convert the hexdump to a file `xxd -r` can be used.

# Level 13 -> 14
The next level can be solved by using the given private ssh-key and login
with the `bandit14` account by:
```bash
ssh bandit14@localhost -i sshkey.private
```

# Level 14 -> 15
The current password is found at `/etc/bandit_pass/bandit14`.
It can be used to send it via tcp (by using `netcat`) to the port 30000 of
the current machine (`localhost`) the service behind that port will answer
with the next password:

```bash
netcat localhost 30000
```

# Level 15 -> 16
The next password is retrieved by sending the current password to the port
30001 using ssl/tls:

```bash
openssl s_client -connect localhost:30001
```

# Level 16 -> 17
Use nmap to scan for all tcp services running on localhost:
```bash
nmap -sT localhost -p 31000-32000
```

Option `-sT` is used for performing a "TCP connect scan". It tries to fully
perform the TCP handshake on every given port. It is normally used when
SYN (`-sS`) scan is not an option (i.e. no privileged user available). It's
important to note that `-sT` creates a lot of noise on the target system because
every TCP connection try will be logged on it.

The scan results in 5 different services. The `openssl s_client` tool can be
used to check for a valid ssl service behind each of these ports. Port `31790`
responds with an RSA-KEY which can be used to login into the next level using
`ssh -l <key> <host>`

# Level 17 -> 18
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

# Level 18 -> 19
The bashrc of the `bandit18` user exits the shell.

To prevent loading of the bashrc we can use `/bin/sh` instead:

```bash
ssh -p 2220 bandit18@bandit.labs.overthewire.org /bin/sh
```

# Level 19 -> 20
For this level you only need to execute the bandit20-do binary which
has the [setuid-bit](https://en.wikipedia.org/wiki/Setuid#When_set_on_an_executable_file) set and invokek cat to print the password:

```bash
./bandit20-do cat /etc/bandit_pass/bandit20
```

# Level 20 -> 21
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
# Level 21 -> 22
The level task says there is a cronjob configured which can be found under
`/etc/cron.d/`:

```bash
#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```

As the file that is being written to can be read as any user we can just use
`cat` to get the next password that it contains.
Yk7owGAcWjwMVRwrTesJEwB7WVOiILLI

# Level 22 -> 23



jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n
