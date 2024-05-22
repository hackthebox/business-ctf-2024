![](../../../../../assets/logo_htb.png)



<img src="../../../../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align=left />    	<font size="10">Locked Away</font>

​		30<sup>th</sup> April 2024

​		Prepared By: ir0nstone

​		Challenge Author(s): ir0nstone

​		Difficulty: <font color=green>Easy</font>

​		Classification: Official

 



# Synopsis

Locked Away is an Easy difficulty misc challenge that features a PyJail with blacklisted strings.

# Description

A test! Getting onto the team is one thing, but you must prove your skills to be chosen to represent the best of the best. They have given you the classic - a restricted environment, devoid of functionality, and it is up to you to see what you can do. Can you break open the chest? Do you have what it takes to bring humanity from the brink?

## Skills Required

- Basic Python

## Skills Learned

- Research Skills

# Enumeration

We are given the source code in `main.py`. It's very simple:

```python
banner = r'''
.____                  __              .___    _____                        
|    |    ____   ____ |  | __ ____   __| _/   /  _  \__  _  _______  ___.__.
|    |   /  _ \_/ ___\|  |/ // __ \ / __ |   /  /_\  \ \/ \/ /\__  \<   |  |
|    |__(  <_> )  \___|    <\  ___// /_/ |  /    |    \     /  / __ \\___  |
|_______ \____/ \___  >__|_ \\___  >____ |  \____|__  /\/\_/  (____  / ____|
        \/          \/     \/    \/     \/          \/             \/\/     
'''


def open_chest():
    with open('flag.txt', 'r') as f:
        print(f.read())


blacklist = [
    'import', 'os', 'sys', 'breakpoint',
    'flag', 'txt', 'read', 'eval', 'exec',
    'dir', 'print', 'subprocess', '[', ']',
    'echo', 'cat', '>', '<', '"', '\'', 'open'
]

print(banner)

while True:
    command = input('The chest lies waiting... ')

    if any(b in command for b in blacklist):
        print('Invalid command!')
        continue

    try:
        exec(command)
    except Exception:
        print('You have been locked away...')
        exit(1337)
```

In effect, our input is passed against a blacklist. If any of the blacklisted strings are present, it is rejected. 
Otherwise, it is passed to `exec()`, for obvious code execution. If we call `open_chest()`, we can get the flag. An 
invalid command ends the process early, so boolean-based extraction is out of the question. It's a classic PyJail 
challenge!

# Solution
We can't call `open_chest()` directly, as `open` is blocked by the blacklist.

How do we bypass the blacklist? While there are likely numerous ways, the way we'll present here is probably the 
simplest. Instead of bypassing it, we'll **overwrite** it.

An initial thought could be to do so using the following:

```python
blacklist = []
```

This, however, contains 2 blocked characters: `[` and `]`. A little bit of research may lead the user to the 
[Python list's `clear()` function](https://www.programiz.com/python-programming/methods/list/clear), which will empty 
the array. This contains none of the blacklisted strings!

```python
blacklist.clear()
```

Once it is cleared, we can use any Python code we want to read the flag.

```python
open_chest()
```

This will return the flag!
