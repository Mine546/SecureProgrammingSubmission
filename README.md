# SecureProgrammingSubmission: Archie Rowe (a1226064), Jarrod Hackett (a1864980), Kien Nguyen (a1860464), Michael Economou (a1860989)
__________________________________________________________________________________________________________________________________
Setting up the system:

To run this program, You will need vcpkg which can be downloaded from: https://github.com/microsoft/vcpkg 
If you don't yet have it you can by running --> git clone https://github.com/microsoft/vcpkg 

Then you will need to bootstrap firstly by accessing vcpkg directory: 
cd vcpkg

Then depending on if you are running on Windows or Linux/macOS:
.\bootstrap-vcpkg.bat # For Windows
./bootstrap-vcpkg.sh  # For Linux/macOS

After this is installed, you will need access to nlohmann/json, openssl, and websocketpp, which can be downloaded by:
./vcpkg install nlohmann-json websocketpp openssl

This may take a couple minutes...

Given the CMakeLists.txt, before running the code ensure to change the following lines below (Replacing <path-to-vcpkg> with the actual path to vcpkg folder):
set(CMAKE_TOOLCHAIN_FILE "<path-to-vcpkg>/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
include_directories("/home/kien/PACKAGE/Secure-Programming-Assignment/vcpkg/installed/x64-linux/include")
_________________________________________________________________________________________________________________________________________________________
EXAMPLE -->  set(CMAKE_TOOLCHAIN_FILE "/home/name/chatsystem/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
where chatsystem is the directory that the client.cpp and server.cpp is located
Make sure that client.cpp and server.cpp are not in the vcpkg directory
_________________________________________________________________________________________________________________________________________________________

You will then need to make a build to run it in (make directory, go to directory, call cmake on previous directory, and build a cmake project)
Make sure you are then in the directory where all the code is(client.cpp & server.cpp), adjacent to vcpkg.
mkdir build
cd build
cmake -DCMAKE_TOOLCHAIN_FILE=<path-to-vcpkg>/vcpkg/scripts/buildsystems/vcpkg.cmake ..
cmake ..
make

___________________________________________________________________________________________________________________________________________________
Now you are ready to run the code.
client.cpp and server.cpp need to be compiled seperately (with server being run first) (Ensuring that you are in the build directory)
The server can be run by: 
./main

Clients can then be run by opening as many tabs/terminals and typing in the terminal:
./client

Ensure you change the parameter in the main function of client and server to the desired IP, depending on which server you wish to connect to.


In order to send a message, read the following: 

Public Message:

    When prompted for the message type, enter public.
    Then enter the public message you want to send. This message will be sent to all connected clients.

Private Message:

    When prompted for the message type, enter private.
    Enter the encrypted message you want to send. This message must be encrypted using AES before sending.
    Provide the recipient(s) as a comma-separated list of their public keys (PEM format). The code will encrypt the AES key with each recipient's public key and send the message
