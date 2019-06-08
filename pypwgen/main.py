#!/usr/bin/env python3

# MIT License
#
# Copyright (c) 2019 Michael Chapman
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# based on pwgen (https://sourceforge.net/projects/pwgen/)

import argparse
import secrets
import sys

from enum import Flag, auto


class Element(Flag):
    CONSONANT = auto()
    VOWEL = auto()
    DIPTHONG = auto()
    NOT_FIRST = auto()


class Option(Flag):
    NONE = 0
    DIGITS = auto()
    UPPERS = auto()
    SYMBOLS = auto()
    AMBIGUOUS = auto()
    NO_VOWELS = auto()


MAX_LENGTH = 64

DIGITS = list('0123456789')
UPPERS = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
LOWERS = list('abcdefghijklmnopqrstuvwxyz')
SYMBOLS = list('!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~')
AMBIGUOUS = set('B8G6I1l0OQDS5Z2')
VOWELS = list('01aeiouyAEIOUY')

ELEMENTS = [
    ('a', Element.VOWEL),
    ('ae', Element.VOWEL | Element.DIPTHONG),
    ('ah', Element.VOWEL | Element.DIPTHONG),
    ('ai', Element.VOWEL | Element.DIPTHONG),
    ('b', Element.CONSONANT),
    ('c', Element.CONSONANT),
    ('ch', Element.CONSONANT | Element.DIPTHONG),
    ('d', Element.CONSONANT),
    ('e', Element.VOWEL),
    ('ee', Element.VOWEL | Element.DIPTHONG),
    ('ei', Element.VOWEL | Element.DIPTHONG),
    ('f', Element.CONSONANT),
    ('g', Element.CONSONANT),
    ('gh', Element.CONSONANT | Element.DIPTHONG | Element.NOT_FIRST),
    ('h', Element.CONSONANT),
    ('i', Element.VOWEL),
    ('ie', Element.VOWEL | Element.DIPTHONG),
    ('j', Element.CONSONANT),
    ('k', Element.CONSONANT),
    ('l', Element.CONSONANT),
    ('m', Element.CONSONANT),
    ('n', Element.CONSONANT),
    ('ng', Element.CONSONANT | Element.DIPTHONG | Element.NOT_FIRST),
    ('o', Element.VOWEL),
    ('oh', Element.VOWEL | Element.DIPTHONG),
    ('oo', Element.VOWEL | Element.DIPTHONG),
    ('p', Element.CONSONANT),
    ('ph', Element.CONSONANT | Element.DIPTHONG),
    ('qu', Element.CONSONANT | Element.DIPTHONG),
    ('r', Element.CONSONANT),
    ('s', Element.CONSONANT),
    ('sh', Element.CONSONANT | Element.DIPTHONG),
    ('t', Element.CONSONANT),
    ('th', Element.CONSONANT | Element.DIPTHONG),
    ('u', Element.VOWEL),
    ('v', Element.CONSONANT),
    ('w', Element.CONSONANT),
    ('x', Element.CONSONANT),
    ('y', Element.CONSONANT),
    ('z', Element.CONSONANT)
]


def phonemes(size, options=Option.NONE):
    pw = ''
    prev = None
    should_be = secrets.choice([Element.CONSONANT, Element.VOWEL])
    unhandled = options & ~Option.AMBIGUOUS
    while len(pw) < size:
        e = secrets.choice(ELEMENTS)
        if e[1] & Element.NOT_FIRST and len(pw) == 0:
            continue
        if not e[1] & should_be:
            continue
        if (prev and prev & Element.VOWEL and e[1] & Element.VOWEL and
                e[1] & Element.DIPTHONG):
            continue
        if size < len(pw) + len(e[0]):
            continue
        if options & Option.AMBIGUOUS and any([c in AMBIGUOUS for c in e[0]]):
            continue
        if options & Option.UPPERS and (len(pw) == 0 or e[1] & Element.CONSONANT) and secrets.randbelow(10) < 2:
            e = (e[0].title(), e[1])
            if options & Option.AMBIGUOUS and any([c in AMBIGUOUS for c in e[0]]):
                continue
            unhandled &= ~Option.UPPERS
        pw += e[0]
        if len(pw) == size:
            break
        if options & Option.DIGITS and len(pw) > 0 and secrets.randbelow(10) < 3:
            d = secrets.choice(DIGITS)
            while options & Option.AMBIGUOUS and d in AMBIGUOUS:
                d = secrets.choice(DIGITS)
            pw += d
            prev = None
            should_be = secrets.choice([Element.CONSONANT, Element.VOWEL])
            unhandled &= ~Option.DIGITS
            continue
        if options & Option.SYMBOLS and len(pw) > 0 and secrets.randbelow(10) < 2:
            s = secrets.choice(SYMBOLS)
            while options & Option.AMBIGUOUS and s in AMBIGUOUS:
                s = secrets.choice(SYMBOLS)
            pw += s
            unhandled &= ~Option.SYMBOLS
        if should_be & Element.CONSONANT:
            should_be = Element.VOWEL
        else:
            if (prev and prev & Element.VOWEL) or e[1] & Element.DIPTHONG or secrets.randbelow(10) < 7:
                should_be = Element.CONSONANT
            else:
                should_be = Element.VOWEL
        prev = e[1]
    if unhandled:
        return phonemes(size, options)
    return pw


def password(size, options=Option.NONE):
    def a_in_b(a, b):
        for e in a:
            if e in b:
                return True
        return False
    pw = ''
    pool = LOWERS
    option_count = 0
    if options & Option.DIGITS:
        pool += DIGITS
        option_count += 1
    if options & Option.UPPERS:
        pool += UPPERS
        option_count += 1
    if options & Option.SYMBOLS:
        pool += SYMBOLS
        option_count += 1
    if options & Option.AMBIGUOUS:
        pool = [e for e in pool if e not in AMBIGUOUS]
    while len(pw) < size:
        pw += secrets.choice(pool)
    if size > option_count:
        if options & options.UPPERS and not a_in_b(UPPERS, pw):
            return password(size, options)
        if options & options.DIGITS and not a_in_b(DIGITS, pw):
            return password(size, options)
        if options & options.SYMBOLS and not a_in_b(SYMBOLS, pw):
            return password(size, options)
    return pw


def main():
    parser = argparse.ArgumentParser(prog='pypwgen', description='Generate easier to remember passwords.')
    parser.add_argument('size', nargs='?', type=int, default=12, help='size of password (1-64, default 12)')
    parser.add_argument('-A', action='store_true', help='exclude uppercase letters')
    parser.add_argument('-0', action='store_true', help='exclude numerals', dest='zero')
    parser.add_argument('-y', action='store_true', help='include at least one symbol')
    parser.add_argument('-b', action='store_true', help='avoid ambiguous characters')
    parser.add_argument('-s', action='store_true', help='generate random password')
    args = parser.parse_args()
    options = Option.DIGITS | Option.UPPERS
    if args.size < 1:
        args.size = 1
    args.size = min(args.size, MAX_LENGTH)
    if args.A:
        options &= ~Option.UPPERS
    if args.zero:
        options &= ~Option.DIGITS
    if args.y:
        options |= Option.SYMBOLS
    if args.b:
        options |= Option.AMBIGUOUS
    if args.s or args.size < 5:
        print(password(args.size, options))
    else:
        print(phonemes(args.size, options))
    return 0


if __name__ == '__main__':
    sys.exit(main())
