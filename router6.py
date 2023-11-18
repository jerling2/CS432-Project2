from router import Router


def main():
    router = Router('127.0.0.1', 8006)
    router.open()
    router.load_router_table('./input/router_6_table.csv')
    while True:
        router.on_connect()
        

if __name__ == '__main__':
    main()