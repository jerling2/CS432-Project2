################################################################################
###~- ROUTER 3 -~#~- ROUTER 3 -~#~- ROUTER 3 -~#~- ROUTER 3 -~#~- ROUTER 3 -~###
################################################################################
# ---------------------------------------------------------------------------- #
# ---------------------- Router Network Topology Diagram --------------------- #
#                                 ┌┄┄┄┐              ┌┄┄┄┐                     #
#                          ◁ 8002 | 2 | d ▷┄┄┄◁ 8003 █*3*|                     #
#                        ╱        └┄┄┄┘              └┄┄┄┘                     #
#                       △           c                                          #
#                       a           ▽                                          #
#                     ┌┄┄┄┐         ┊                                          #
#                8001 | 1 |         ┊                                          #
#                     └┄┄┄┘         ┊                                          #
#                       b           △                                          #
#                       ▽  	       8004                                        #
#                        ╲        ┌┄┄┄┐              ┌┄┄┄┐                     #
#                          ◁ 8004 | 4 | e ▷┄┄┄◁ 8005 | 5 |                     #
#                                 └┄┄┄┘              └┄┄┄┘                     #
#                                   f                                          #
#                                   ▽                                          #
#                                    ╲               ┌┄┄┄┐                     #
#                                      ┄┄┄┄┄┄ ◁ 8006 | 6 |                     #
#                                                    └┄┄┄┘                     #
# ---------------------------------------------------------------------------- #
# ---------------------------------------------------------------------------- #
from router import Router


def main():
    router = Router('127.0.0.1', 8003)
    router.open()
    router.load_router_table('./input/router_3_table.csv')
    while True:
        router.on_connect()
        

if __name__ == '__main__':
    main()