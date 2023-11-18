from router import Router


def main():
    router = Router('127.0.0.1', 8002)
    router.open()
    router.load_router_table('./input/router_2_table.csv')
    router.connect_to('127.0.0.1', '8003', 'd')
    router.connect_to('127.0.0.1', '8004', 'c')
    while True:
        router.on_connect()
        

if __name__ == '__main__':
    main()