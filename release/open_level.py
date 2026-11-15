
import os
import struct
import shutil
import sys
from pathlib import Path
from getpass import getpass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag


ENC_MAGIC = b"P565ENC1"
PKG_MAGIC = b"P565PKG1"

MAX_FILES = 100
MAX_NAME_LENGTH = 255


def choose_container(folder):
    if len(sys.argv) > 1:
        source = Path(sys.argv[1])
        if not source.is_absolute():
            source = folder / source
        return source

    files = sorted(folder.glob("*.p565"))

    if not files:
        raise ValueError("В этой папке не найдено файлов .p565.")

    if len(files) == 1:
        return files[0]

    print("Найдено несколько контейнеров:")
    for i, file in enumerate(files, 1):
        print(f"  {i}. {file.name}")

    choice = input("Выберите номер файла: ").strip()

    if not choice.isdigit() or not 1 <= int(choice) <= len(files):
        raise ValueError("Некорректный номер.")

    return files[int(choice) - 1]


def decrypt_container(source, password):
    data = source.read_bytes()

    if len(data) < 52:
        raise ValueError("Контейнер слишком короткий.")

    magic = data[:8]
    if magic != ENC_MAGIC:
        raise ValueError("Неизвестный формат контейнера.")

    salt = data[8:24]
    nonce = data[24:36]
    ciphertext = data[36:]

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=32768,
        r=8,
        p=1
    )

    key = kdf.derive(password.encode("utf-8"))
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, magic)

    if not plaintext.startswith(PKG_MAGIC):
        raise ValueError("Расшифрованные данные имеют неизвестный формат.")

    return plaintext


def unpack_package(package):
    if not package.startswith(PKG_MAGIC):
        raise ValueError("Неверный формат пакета.")

    pos = len(PKG_MAGIC)

    if len(package) < pos + 4:
        raise ValueError("Повреждённый пакет.")

    file_count = struct.unpack_from(">I", package, pos)[0]
    pos += 4

    if file_count > MAX_FILES:
        raise ValueError("Слишком много файлов в пакете.")

    result = {}

    for _ in range(file_count):
        if pos + 2 > len(package):
            raise ValueError("Повреждённое имя файла.")

        name_length = struct.unpack_from(">H", package, pos)[0]
        pos += 2

        if not 1 <= name_length <= MAX_NAME_LENGTH:
            raise ValueError("Некорректная длина имени файла.")

        if pos + name_length > len(package):
            raise ValueError("Пакет обрезан.")

        try:
            name = package[pos:pos + name_length].decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("Некорректное имя файла.")

        pos += name_length

        if (
            name in ("", ".", "..")
            or "/" in name
            or "\\" in name
            or ":" in name
        ):
            raise ValueError("Недопустимое имя файла.")

        if name in result:
            raise ValueError("В пакете есть повторяющиеся имена файлов.")

        if pos + 8 > len(package):
            raise ValueError("Повреждён размер файла.")

        data_length = struct.unpack_from(">Q", package, pos)[0]
        pos += 8

        if data_length > len(package) - pos:
            raise ValueError("Данные файла обрезаны.")

        result[name] = package[pos:pos + data_length]
        pos += data_length

    if pos != len(package):
        raise ValueError("В пакете обнаружены лишние данные.")

    return result


def main():
    folder = Path(__file__).resolve().parent

    try:
        source = choose_container(folder)

        if not source.exists():
            raise ValueError(f"Файл не найден: {source.name}")

        print(f"\nКонтейнер: {source.name}")
        password = getpass("Введите пароль: ")

        print("Расшифровка...")

        package = decrypt_container(source, password)

        print("Пароль верный. Распаковка...")

        files = unpack_package(package)

        # Для outer.p565 создаём level_1,
        # для level_2.p565 — level_2 и так далее.
        output_name = (
            "level_1" if source.stem == "outer"
            else source.stem
        )

        output_dir = source.parent / output_name

        if output_dir.exists():
            raise ValueError(
                f"Папка {output_name} уже существует. "
            )

        output_dir.mkdir()

        try:
            for name, content in files.items():
                (output_dir / name).write_bytes(content)

            shutil.copy2(
                Path(__file__),
                output_dir / Path(__file__).name
            )

        except Exception:
            shutil.rmtree(output_dir, ignore_errors=True)
            raise

        print("\nУровень успешно открыт!")
        print(f"Папка: {output_dir}")
        print("\nПолученные файлы:")

        for name, content in files.items():
            print(f"  {name} ({len(content)} байт)")

        print("\nРешите задачу и запустите open_level.py снова,")
        print("чтобы открыть следующий уровень.")

        task = output_dir / "task.txt"
        if task.exists() and os.name == "nt":
            os.startfile(task)

    except InvalidTag:
        print("\nОшибка: неверный пароль или повреждённый контейнер.")

    except Exception as error:
        print(f"\nОшибка: {error}")


if __name__ == "__main__":
    main()
