Name: Yiliang Liu
StudentID: V00869672

This is the readme for TCPTrafficAnalysis.py. The program is used to go through a cap file and analysis the content
within the targeted file

How to run this program?
Python 3.6 is required to run this program.
To run this program, type:
python3 TCPTrafficAnalysis.py <caplife.cap>
For example:
python3 TCPTrafficAnalysis.py sample-capture-file.cap

How does this program work?
This program will read the file and go through the whole cap file byte by byte, while analysis the content. This program
has only been tested with the provided sample input. There's some error handling, but it won't be able to compeletely
handle a faulty cap file.