from router import Router

def main():
    router = Router()
    router.listen(8001)
    table = router.read_csv("../input/router_1_table.csv")
    router.find_default_gateway(table)
    router.generate_forwarding_table_with_range(table)


if __name__ == '__main__':
    main()