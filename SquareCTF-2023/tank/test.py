#!/usr/bin/python3

import math


def calculate_projectile_landing_point(v0, theta):
    theta_rad = math.pi * theta / 180.0
    vx = math.cos(theta_rad) * v0
    vy = math.sin(theta_rad) * v0
    landing_point = vx * (2 * vy / 9.81)
    print(f"Projectile will land at x = {int(landing_point)} meters")
    return landing_point


# Example usage
v0 = 24.462420158275428  # initial velocity in m/s
theta = 45  # angle in degrees
calculate_projectile_landing_point(v0, theta)
