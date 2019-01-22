James Nance & Jay Glover

We used a parser for json that we found online, then created our lua files. The testing was done in wireshark before starting the c programming to ensure accuracy. 
In order to run the program, make sure to be in the directory dissector for compiling the c program.
once in the directory in the terminal, simply type make
you will then be prompted to enter a json file. 
Type any of the following:
icmp.json
rtp.json
rip.json

to send to wireshark we used 
sudo cp output.lua /usr/lib/x86_64-linux-gnu/wireshark/plugins/2.6
 
At this point the capture can be filed and ctrl+shift+L may be used to test our Lua script. 