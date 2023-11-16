from router import Router


def main():
    router = Router()
    router.open('127.0.0.1', 8001)
    router.load_router_table('../input/router_1_table.csv')
    ip_bin = router.ip_to_bin('10.0.0.227')
    print(router.lpm(ip_bin, '10.0.0.227'))

    # router.connect_to('127.0.0.1', 8002)


if __name__ == '__main__':
    main()