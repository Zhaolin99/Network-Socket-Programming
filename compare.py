import argparse
import hashlib
import chardet


def compare_files(files):
    """Compare MD5 hashes of files, return True if they are the same"""

    hashes = []

    for file in files:
        encoding = chardet.detect(open(file, 'rb').read())['encoding']
        with open(file, 'r', encoding=encoding) as f:
            hashes.append(hashlib.md5(f.read().encode()).hexdigest())

    # return True if all hashes are the same
    return all(x == hashes[0] for x in hashes)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    # add arguments for multiple files
    parser.add_argument('files', nargs='+', type=str)
    args = parser.parse_args()
    print(compare_files(args.files))

