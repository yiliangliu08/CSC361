Name: Yiliang Liu
StudentID: V00869672

This is the readme for SmartClient.py. The program is used to determine whether a URL is supported by
https/http1.1/http2 and find the cookie that has been used.

How to run this program?
Python 3.6 is required to run this program.
To run this program, type:
python3 SmartClient.py <www.example.com>
For example:
python3 SmartClient.py www.uvic.ca

How does this program work?
This program will send a request to the website, and retrieve the response.
First, the program will test if https is supported. If response 200 is returned. The program
will continue to test http2 connection. If a redirect is returned, and location is provided, the program will redirect
to the new address. Test result and cookie used will be recorded and displayed at output.