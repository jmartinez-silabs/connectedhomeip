# CHIP EFR32 Lock Example

An example showing the use of CHIP over WIFI on the Silicon Labs EFR32 MG12 
using the wifi explansion board WF-200.

<hr>

-   [CHIP EFR32 Lock Example](#chip-efr32-lock-example)
    -   [Introduction](#introduction)
    -   [Building](#building)
        -   [Note](#note)
    -   [Flashing the Application](#flashing-the-application)
    -   [Viewing Logging Output](#viewing-logging-output)
    -   [Running the Complete Example](#running-the-complete-example)
        -   [Notes](#notes)

<hr>

<a name="intro"></a>

## Introduction

The EFR32 lock example provides a baseline demonstration of a door lock device
built using CHIP and the Silicon Labs gecko SDK. The example use WIFI communications
using the WF-200 expansion board. 

The lock example is intended to serve both as a means to explore the workings of
CHIP as well as a template for creating real products based on the Silicon Labs
platform.

<a name="building"></a>

## Building

-   Download the [sdk_support](https://github.com/SiliconLabs/sdk_support) from
    GitHub and export the path with :

            $ export EFR32_SDK_ROOT=<Path to cloned git repo>

-   Download the
    [Simplicity Commander](https://www.silabs.com/mcu/programming-options)
    command line tool, and ensure that `commander` is your shell search path.
    (For Mac OS X, `commander` is located inside
    `Commander.app/Contents/MacOS/`.)

-   Download and install a suitable ARM gcc tool chain:
    [GNU Arm Embedded Toolchain 9-2019-q4-major](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm/downloads)

-   Install some additional tools(likely already present for CHIP developers):

           # Linux
           $ sudo apt-get install git libwebkitgtk-1.0-0 ninja-build

           # Mac OS X
           $ brew install ninja

-   Currently Supported hardware:

    MG12 boards:

    -   BRD4161A / SLWSTK6000B / Wireless Starter Kit / 2.4GHz@19dBm
    -   BRD4163A / SLWSTK6000B / Dual band Wireless Starter Kit / 2.4GHz@19dBm, 868MHz@19dBm
    -   BRD4164A / SLWSTK6000B / Dual band Wireless Starter Kit / 2.4GHz@19dBm, 915MHz@19dBm

*   Build the example application:

        cd ~/connectedhomeip/
        git submodule update --init
        export EFR32_SDK_ROOT=<path-to-silabs-sdk-v2.7>
        export EFR32_BOARD=BRD4161A
        ./scripts/examples/gn_efr32_example.sh examples/lock-app/wf200/ out/efr32_wfx_lock_app

-   To delete generated executable, libraries and object files use:

        cd ~/connectedhomeip/
        rm -rf out/efr32_wfx_lock_app

<a name="flashing"></a>

## Flashing the Application

-   On the command line:

        cd ~/connectedhomeip/out/efr32_wfx_lock_app
        python3 out/debug/chip-wf200-lock-example.flash.py

-   Or with the Ozone debugger, just load the .out file.
-   Or with the Commander, just load the .s37 file.

<a name="view-logging"></a>

## Viewing Logging Output

The example application is built to use the SEGGER Real Time Transfer (RTT)
facility for log output. RTT is a feature built-in to the J-Link Interface MCU
on the WSTK development board. It allows bi-directional communication with an
embedded application without the need for a dedicated UART.

Using the RTT facility requires downloading and installing the _SEGGER J-Link
Software and Documentation Pack_
([web site](https://www.segger.com/downloads/jlink#J-LinkSoftwareAndDocumentationPack)).
Alternatively the _SEGGER Ozone - J-Link Debugger_ can be used to view RTT logs.

-   Download the J-Link installer by navigating to the appropriate URL and
    agreeing to the license agreement.

-   [JLink_Linux_x86_64.deb](https://www.segger.com/downloads/jlink/JLink_Linux_x86_64.deb)
-   [JLink_MacOSX.pkg](https://www.segger.com/downloads/jlink/JLink_MacOSX.pkg)

*   Install the J-Link software

          cd ~/Downloads
          sudo dpkg -i JLink_Linux_V*_x86_64.deb

*   In Linux, grant the logged in user the ability to talk to the development
    hardware via the linux tty device (/dev/ttyACMx) by adding them to the
    dialout group.

          sudo usermod -a -G dialout ${USER}

Once the above is complete, log output can be viewed using the JLinkExe tool in
combination with JLinkRTTClient as follows:

-   Run the JLinkExe tool with arguments to autoconnect to the WSTK board:

    For MG12 use:

          JLinkExe -device EFR32MG12PXXXF1024 -if JTAG -speed 4000 -autoconnect 1

    For MG21 use:

          JLinkExe -device EFR32MG21AXXXF1024 -if SWD -speed 4000 -autoconnect 1

-   In a second terminal, run the JLinkRTTClient to view logs:

          JLinkRTTClient

<a name="running-complete-example"></a>

## Running the Complete Example

-   Once the example is flashed on the board, the WiFi informations needed to connected 
    to the access point has to be provisioned to the device 
    This is done through a Bluetooth Low Energy connection using the Secure Rendez-vous procedure

- You can do so with the Chip-tool
    To build the Chip-tool run this script
        cd ~/connectedhomeip/
        ./scripts/examples/gn_build_example.sh examples/chip-tool out/debug/standalone
    
    Start the BLE paring sequence
        ./out/debug/standalone/chip-tool pairing ble <SSID> <PASSWORD> <SETUP_PINCODE> <DISCRIMINATOR>

        For our example the Pin code and Discriminator are preset to "12345678" "3840"
        ./out/debug/standalone/chip-tool pairing ble <SSID> <PASSWORD> 12345678 3840

-   Using chip-tool you can now control the lock status with on/off command such
    as `chip-tool onoff on 1`

        ./out/debug/standalone/chip-tool onoff on 1
