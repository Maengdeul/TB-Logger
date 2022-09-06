This is an application runs hash and signing functions in TrustZone for EDR's secure data logging.

This application needs to be run with OP-TEE, an open source framework for ARM TrustZone.

Corresponding paper: **TB-Logger: Secure Vehicle Data Logging Method using Trusted Execution Environment and Blockchain** Dongwoo Kang, Hyo Jin Jo (Revisioning in progress)

# Prerequisites

You can run this application with real TrustZone or simulated one by using QEMU.

**Required System**: Ubuntu-based distributions

For simulation, no additional hardware is needed.

For real TrustZone, and additional board is required. Raspberry Pi 3, Hikey Board, etc. Check this List for more info.

# Setup

# (1) Set up OP-TEE

1. Follow **step1** ~ **step5** in "Get and build the solution" to build the OP-TEE solution.
   https://optee.readthedocs.io/en/latest/building/gits/build.html#get-and-build-the-solution
2. **For real boards**: If you are using boards, keep follow **step6** ~ **step7** in the above link to flash the devices. This step is device-specific.
   **For simulation**: If you have chosen QEMU-v7/v8, run the below command to start QEMU console.
   ```
   make run
   (qemu) c
   ```
3. 
