This C code interposes system networking calls using ld_preload to take over application activity. The code uses linux's raw sockets and controls network (TCP) activity eg, controlling ACKs.

The goals are to:

1- Emulate network between application and server.
2- Observe server behavior in presence of an induced network event. An example of such event can be to emulate loss (by not sending ACK for a packet) adn see how server behaves.
3- This library allows reusing application's SSL/TLS activity without writing our own modules.