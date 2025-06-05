#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This script connects to an ArduCopter SITL drone using pymavlink and forces it to land
at a specific location, overriding any existing waypoint commands.
"""

from time import sleep
from pymavlink import mavutil
import math

lon = 149.165771
lat = -35.36276
alt = 90

HOST = "tcp:localhost:4003"

def connect_to_vehicle():
    global HOST
    print("Connecting to vehicle...")
    vehicle = mavutil.mavlink_connection(HOST)
    vehicle.wait_heartbeat()
    print(f"Heartbeat from system (system {vehicle.target_system} component {vehicle.target_component})")
    return vehicle

def send_waypoint(vehicle, lat, lon, alt):
    print(f"Sending waypoint: {lat:.6f}, {lon:.6f}, {alt}m")
    vehicle.mav.mission_item_send(
        vehicle.target_system,
        vehicle.target_component,
        0,  # seq
        mavutil.mavlink.MAV_FRAME_GLOBAL_RELATIVE_ALT,
        mavutil.mavlink.MAV_CMD_NAV_WAYPOINT,
        2,  # current - set to current waypoint
        1,  # autocontinue
        0, 0, 0, 0,  # param1-4
        lat, lon, alt
    )

def request_position_data(vehicle):
    print("Explicitly requesting position data...")
    # Send a request for position information
    vehicle.mav.request_data_stream_send(
        vehicle.target_system,
        vehicle.target_component,
        mavutil.mavlink.MAV_DATA_STREAM_POSITION,
        10,  # 10 Hz update rate
        1    # Start sending
    )
    # Wait a moment for data to start flowing
    sleep(1)
    # Now try to get position
    return get_current_position(vehicle)

def get_current_position(vehicle):    
    print(f"Trying to get position from GLOBAL_POSITION_INT...")
    msg = vehicle.recv_match(type="GLOBAL_POSITION_INT", blocking=True, timeout=3)
    if msg:
        print(f"Received GLOBAL_POSITION_INT message")
            
        lat = msg.lat / 1e7
        lon = msg.lon / 1e7
        alt = msg.relative_alt / 1000.0
        return lat, lon, alt
                
    print("Could not get position from any message type")
    return None, None, None

def positions_close(lat1, lon1, lat2, lon2, decimal_places=3):
    
    def truncate(f, n):
        factor = 10.0 ** n
        return math.trunc(f * factor) / factor

    return truncate(lat1, decimal_places) == truncate(lat2, decimal_places) and \
           truncate(lon1, decimal_places) == truncate(lon2, decimal_places)

def land(vehicle):
    vehicle.mav.set_mode_send(
        vehicle.target_system,
        mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED,
        vehicle.mode_mapping()["LAND"]
    )

uav = connect_to_vehicle()

while True:
    print("Sending point...")
    send_waypoint(uav, lat=lat, lon=lon, alt=alt)
    
    cur_lat, cur_lon, cur_alt = request_position_data(uav)
    print(f"[+] Current location: {cur_lat}, {cur_lon}")

    if cur_lon != None and cur_lat != None:
        print("[*] Checking if reached the base...")
        if positions_close(cur_lat, cur_lon, lat, lon):
            print("[+] Reached target")
            print("Landing...")
            land(uav)
            break

    
    sleep(2)
