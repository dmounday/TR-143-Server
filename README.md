Programs to suport testing of the TR-143 diagnostics for a CWMPc clinet(TR-069).

The TR143_Server listens on the specified port for an HTTP connection and responds to a GET depending on the URI in the GET.
If the URI is of the form TTnnnnnnn it sends data until the client disconnects or the number of seconds specified by nnnnnn expires. 
If the URI is of the form ZZnnnnnnn is send the number of bytes specified by the nnnnnn in chunked encoding format.

