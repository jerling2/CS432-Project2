from router import Router


def main():
    router = Router('127.0.0.1', 8004)
    router.open()
    router.load_router_table('./input/router_4_table.csv')
    router.connect_to('127.0.0.1', '8005', 'e')
    router.connect_to('127.0.0.1', '8006', 'f')
    while True:
        router.on_connect()
        

if __name__ == '__main__':
    main()