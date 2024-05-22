![](../../../../../assets/logo_htb.png)



<img src="../../../../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align=left />    	<font size="10">Zephyr</font>

​		10<sup>th</sup> May 2024

​		Prepared By: ir0nstone

​		Challenge Author(s): ir0nstone

​		Difficulty: <font color=orange>Medium</font>

​		Classification: Official

 



# Synopsis

Zephyr is a Medium misc challenge that requires a user to analyse a git repository and SQLite database for hidden information. The user must study old commits, switch branches and pop stashes to extract all 3 parts of the flag.

# Description

MI6's final project, Zephyr, was the most advanced security system in the world. Programmed in the most secure programming language known to man and designed with top-down security, it is truly impenetrable - and now we have it. Can you sniff around and find the three important parts?

## Skills Required

- Basic SQLite and SQl knowledge
- Knowledge of `git` and how branches and stashes work

## Skills Learned

- Analysing `git` logs for changes
- Analysing very simple SQLite databases for information

# Enumeration
Upon extracting the provided zip file, we can see two files (`source.rs` and `database.db`) as well as a `.git/` directory.

# Solution
Looking through `source.rs`, it appears to be a (super-secure!) interface for communicating with `database.db`. We can open up `database.db` using `sqlite3` and see what's there:

![Initial Database](assets/initial_db.svg)

There is nothing there originally. `source.rs` contains nothing interesting. Let's check the git logs:

![Commits](assets/commits.svg)

There was a commit titled `Removing Sensitive Info...`. Let's see what was changed:

![git show](assets/git_show.svg)

It was the database itself. Let's revert back to the commit before that and see what information we can retrieve.

![Commits](assets/got_db.svg)

Boom - what looks like part of a flag! The description hints that there are 3 parts, so there's still more work to be done. We check if there are other branches, and indeed there are - a `w4rri0r-changes` branch, of course! Switching to it and reading `source.rs`, we get another part of the flag.

![Commits](assets/branch_flag.svg)

The final part of the flag, with a little recon, is found in a `stash`. We can extract it using `git stash pop` while we are on `main`, to grab the changes.

![Stash Flag](assets/stash_flag.svg)

Combining the three parts, we get the final flag: `HTB{g0t_tH3_p4s5_gOT_thE_DB_g0T_TH3_sT4sH}`!
