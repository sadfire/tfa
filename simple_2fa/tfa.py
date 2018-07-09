#!/usr/bin/python3.6

import os
from getpass import getpass
from getpass import getuser
from pathlib import Path

import fire
import pyotp
import pyperclip
from Crypto.Cipher import Blowfish
from Crypto.Hash import SHA256


class PasswordException(Exception):
    pass


def file_open(file: Path, mode: str = 'r'):
    return open(str(file), mode)


class TFA:
    __work_path__ = Path("/home/{}/.s_2fa/".format(getuser()))
    __master_password__ = None
    __hints__ = "hints.txt"

    @classmethod
    def init(cls, *, path=None):
        """
        Initialize class.
        :param path: Path of stored crypted keys
        :return:
        """

        if path is not None:
            cls._set_path(path, is_exist=False)

        elif not cls.__work_path__.exists():
            cls.__work_path__.mkdir()

    @classmethod
    def hints(cls, arg: str = None):
        """

        :return: Stored hints
        """
        file = cls.__work_path__ / cls.__hints__

        if arg is not None and "clean" in arg.lower() and file.exists():
            os.remove(file.absolute())
            return "Successful clean up"

        if not file.exists():
            return "No hints"

        with file_open(file, 'r') as file:
            hints = [hint.strip() for hint in file.readlines()]

        if arg is not None:
            hints = tuple(filter(lambda hint: arg in hint or hint in arg or hint, hints))

        return hints

    @classmethod
    def store(cls, name: str, hint: str = None, key: str = None, password: str = None):
        """

        :param name: Name of record
        :param hint: Hint to stored in hints.txt file
        :param key:
        :param password:
        :return:
        """
        if key is None:
            key = cls._get_key()

        password = cls._get_password(password, 'store')

        try:
            data = cls._encode(str.encode(key), password)
            with file_open(cls.__work_path__ / cls._hash(name), 'xb') as file:
                file.write(data)

            cls._store_hint(hint)

        except FileExistsError:
            return "Can't add this data."

        return "Key successfully saved"

    @classmethod
    def create(cls, length: int, name: str, hint: str, password: str = None):
        password = cls._get_password(password, 'create')

        key = pyotp.random_base32(length)
        cls.store(name, hint, key, password)
        return key

    @classmethod
    def get(cls, name: str, password: str = None):
        password = cls._get_password(password, 'get', is_repeat=False)

        name = cls._hash(name)

        with file_open(cls.__work_path__ / name, 'rb') as file:
            key = cls._decode(file.readline(), password)

        key = pyotp.TOTP(key.decode()).now()

        if input("Copy code to clipboard (y:n)? ").upper() in ["Y", 'YES']:
            pyperclip.copy(key)

        return "{} {}".format(key[:3], key[3:])

    @classmethod
    def remove(cls, name: str):
        """
        Remove one key from name

        :param name: String with name if record
        :return: Message
        """
        if input("Are you sure? This action remove this key data (y:n)?").upper() not in ["Y", "YES"]:
            return "Ok"

        name = cls.__work_path__ / cls._hash(name)

        if name.exists():
            os.remove(name)
            print("Success")

        print("Failed")

    @classmethod
    def reset(cls):
        if input("Are you sure? This action reset all data in work dir (y:n)?").upper() in ["Y", "YES"]:

            cls.hints("clean")
            for f in cls.__work_path__.iterdir():
                os.remove(f.absolute())
                return "All done."
        else:
            return "Ok"

    @classmethod
    def _set_path(cls, path: str, is_exist=True):
        if not Path(path).exists() and is_exist is True:
            raise ValueError("Path not exist")

        elif not is_exist:
            Path(path).mkdir()

        cls.__work_path__ = Path(path)

    @classmethod
    def _get_key(cls):
        if input("Copy key from clipboard(y:n): ").upper() in ['Y', 'YES']:
            key = pyperclip.paste()

            if len(key) == 0:
                raise PasswordException("Can't add empty key.")

            print("Len of coped key is %s" % len(key))

            return key
        else:
            return getpass(prompt="Enter key here: ")

    @classmethod
    def _store_hint(cls, name):
        if name is None:
            return
        with file_open(cls.__work_path__ / "hints.txt", 'a') as file:
            file.write(name + '\n')

    @classmethod
    def _get_password(cls, password: str, action_message: str, is_repeat=True):
        if password is not None and cls._check_password(password):
            return password

        elif password is None:
            password = getpass(prompt="Insert a password to {} this key: ".format(action_message))
            if (is_repeat and getpass(prompt="Repeat: ") != password) or not cls._check_password(password):
                raise PasswordException("Password don't match")
            return password

        else:
            raise PasswordException("Do password more secure.")

    @classmethod
    def _decode(cls, data: bytes, password: str):
        return Blowfish.new(str.encode(password), Blowfish.MODE_CFB, cls._get_init(password)).decrypt(data)

    @classmethod
    def _encode(cls, data: bytes, password: str):
        return Blowfish.new(str.encode(password), Blowfish.MODE_CFB, cls._get_init(password)).encrypt(data)

    @classmethod
    def _get_init(cls, password: str) -> bytes:
        if cls.__master_password__ is None:
            return str(cls._hash(password + getuser())).encode()[:8]

        else:
            return str(cls.__master_password__).encode()[:8]

    @classmethod
    def _hash(cls, value: str):
        value = str.encode(value)
        return SHA256.new(value).hexdigest()

    @classmethod
    def _check_password(cls, password: str) -> bool:
        return len(str.encode(password)) > 10


if __name__ == '__main__':
    TFA.init()

    try:
        fire.Fire(TFA)

    except PasswordException as e:
        print(str(e))
