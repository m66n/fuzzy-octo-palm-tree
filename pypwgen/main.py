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
        if options and options & Option.AMBIGUOUS and any([c in AMBIGUOUS for c in e[0]]):
            continue
        if options and options & Option.UPPERS and (len(pw) == 0 or e[1] & Element.CONSONANT) and secrets.randbelow(10) < 2:
            e = (e[0].title(), e[1])
            if options & Option.AMBIGUOUS and any([c in AMBIGUOUS for c in e[0]]):
                continue
            unhandled &= ~Option.UPPERS
        pw += e[0]
        if len(pw) == size:
            break
        if options and options & Option.DIGITS and len(pw) > 0 and secrets.randbelow(10) < 3:
            d = secrets.choice(DIGITS)
            while options & Option.AMBIGUOUS and d in AMBIGUOUS:
                d = secrets.choice(DIGITS)
            pw += d
            prev = None
            should_be = secrets.choice([Element.CONSONANT, Element.VOWEL])
            unhandled &= ~Option.DIGITS
            continue
        if options and options & Option.SYMBOLS and len(pw) > 0 and secrets.randbelow(10) < 2:
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


def password(size, options, remove):
    pass


def main():
    print(phonemes(20, Option.UPPERS | Option.DIGITS | Option.AMBIGUOUS))
    return 0


if __name__ == '__main__':
    sys.exit(main())
