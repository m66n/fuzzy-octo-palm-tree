# fuzzy-octo-palm-tree
A Python 3 CLI password generator

```
usage: pypwgen [-h] [-A] [-0] [-y] [-b] [-s] [-v] [size]

Generate easier to remember passwords.

positional arguments:
  size        size of password (1-64, default 12)

optional arguments:
  -h, --help  show this help message and exit
  -A          exclude uppercase letters
  -0          exclude numerals
  -y          include at least one symbol
  -b, -B      avoid ambiguous characters
  -s          generate random password
  -v          exclude vowels (in conjunction with -s)
```
