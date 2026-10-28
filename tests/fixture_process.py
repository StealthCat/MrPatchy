"""Select a real harmless ELF image, including coreutils shebang installations."""
from pathlib import Path
import shlex
import sys


def sleep_image(path):
    image=Path(path).resolve(strict=True)
    with image.open('rb') as stream:header=stream.read(512)
    if not header.startswith(b'\x7fELF'):
        if not header.startswith(b'#!'):raise ValueError('Sleep fixture is not an ELF image or supported coreutils wrapper')
        arguments=shlex.split(header.splitlines()[0][2:].decode('ascii'))
        if len(arguments)!=2 or arguments[1]!='--coreutils-prog-shebang=sleep' or Path(arguments[0]).name!='coreutils':raise ValueError('Unsupported sleep fixture wrapper')
        image=Path(arguments[0]).resolve(strict=True)
        with image.open('rb') as stream:header=stream.read(4)
    if not header.startswith(b'\x7fELF'):raise ValueError('Sleep fixture interpreter is not an ELF image')
    return image


if __name__=='__main__':print(sleep_image(sys.argv[1]))
