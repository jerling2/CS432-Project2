from router import Router


def main():
    router = Router()
    router.open('127.0.0.1', 8002)
    router.load_router_table('../input/router_2_table.csv')
    while True:
        router.on_connect()


if __name__ == '__main__':
    main()